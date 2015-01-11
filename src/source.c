/*	--*- c -*--
 * Copyright (C) 2014 Enrico Scholz <enrico.scholz@ensc.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include "source.h"

#include <unistd.h>
#include <time.h>
#include <signal.h>

#include <sys/epoll.h>
#include <sys/timerfd.h>

#include <ensc-lib/list.h>
#include <ensc-lib/io.h>
#include <ensc-lib/safe_calloc.h>
#include <ensc-lib/strbuf.h>
#include <ensc-lib/timespec.h>

#include "failban.h"
#include "rules.h"
#include "logging.h"
#include "util.h"

#define DEBUG_CATEGORY	4

struct parser_context {
	struct list_head	blocked_items;
	struct subprocess	*proc;
	bool			can_reopen;
};

struct epoll_handler {
	bool			(*fn)(struct epoll_handler *, int epoll_fd,
				      uint32_t events);
	struct environment	*env;
	int			fd;
};

struct source_handler {
	struct epoll_handler	h;
	struct source		*s;
	struct strbuf		*buf;
};

static int xclock_gettime(struct timespec *tp)
{
	int		rc = -1;
#ifdef NO_CLOCK_BOOTTIME
	int const	have_clock_boottime = 0;
#else
	/* autodetect support of CLOCK_BOOTTIME at runtime */
	static int	have_clock_boottime = -1;
#endif

#ifndef NO_CLOCK_BOOTTIME
	if (have_clock_boottime != 0) {
		/* supported since 2.6.39 */
		rc = clock_gettime(CLOCK_BOOTTIME, tp);
		if (have_clock_boottime != -1)
			;		/* noop */
		else if (rc < 0 && errno == EINVAL)
			have_clock_boottime = 0;
		else
			have_clock_boottime = 1;
	}
#endif

	if (have_clock_boottime == 0)
		rc = clock_gettime(CLOCK_MONOTONIC, tp);

	return rc;
}

static int xtimerfd_create(int flags)
{
	int		fd = -1;
#ifdef NO_CLOCK_BOOTTIME
	int const	have_clock_boottime = 0;
#else
	/* autodetect support of CLOCK_BOOTTIME at runtime */
	static int	have_clock_boottime = -1;
#endif

#ifndef NO_CLOCK_BOOTTIME
	if (have_clock_boottime != 0) {
		/* supported since 3.14 */
		fd = timerfd_create(CLOCK_BOOTTIME, flags);
		if (have_clock_boottime != -1)
			;		/* noop */
		else if (fd < 0 && errno == EINVAL)
			have_clock_boottime = 0;
		else
			have_clock_boottime = 1;
	}
#endif

	if (have_clock_boottime == 0)
		fd = timerfd_create(CLOCK_MONOTONIC, flags);

	return fd;
}


static bool sources_register_source(int epollfd, struct source_handler *hdl)
{
	struct source		*s = hdl->s;
	struct epoll_event	ev = {
		.events		= EPOLLIN|EPOLLHUP,
		.data		= { .ptr = &hdl->h },
	};
	int			rc;

	BUG_ON(!s);

	rc = epoll_ctl(epollfd, EPOLL_CTL_ADD, s->fd, &ev);
	if (rc < 0) {
		lerr("epoll_ctl(ADD, source/%s): %m",
			s->name);
		goto out;
	}

out:
	return rc >= 0;

}


static void sources_block(struct environment *env,
			  struct rule const *rule,
			  struct trigger *trigger,
			  struct timespec const *now)
{
	struct parser_context	*ctx = env->ctx.parser;
	bool			is_new;
	struct list_head	*prev_head = NULL;

	is_new = (trigger->eob.tv_sec == 0 && trigger->eob.tv_nsec == 0);

	BUG_ON( is_new && !list_empty(&trigger->head));
	BUG_ON(!is_new &&  list_empty(&trigger->head));

	trigger->eob = *now;
	timespec_add_ns(&trigger->eob, 1000000000ull * rule->ban_duration);

	list_del_init(&trigger->head);

	if (is_new) {
		char	ipbuf[INET6_ADDRSTRLEN];
		int	out_fd = ctx->proc->fd_parser_to_filter;

		if (!write_all(out_fd, "+", 1) ||
		    !write_all(out_fd, trigger, sizeof *trigger)) {
			lwarn("failed to send + item to filter");
			trigger_free(trigger);
			goto out;
		}

		log_msg(L_INFO, DEBUG_CATEGORY, "blocked " TRIGGER_FMT,
			TRIGGER_ARG(trigger, ipbuf));
	}

	for (prev_head = ctx->blocked_items.prev;
	     prev_head != &ctx->blocked_items;
	     prev_head = prev_head->prev) {
		struct trigger	*prev_trigger =
			list_entry(prev_head, struct trigger, head);

		if (timespec_before(&prev_trigger->eob, &trigger->eob))
			break;
	}

	list_add(&trigger->head, prev_head);

out:
	return;
}

static void sources_handle_line(struct environment *env,
				struct source *s,
				struct strbuf *str)
{
	struct rule		*rule;
	struct timespec		now;

	ldbg("handle line '%.*s'", (int)str->len, str->b);

	xclock_gettime(&now);

	list_foreach_entry(rule, &env->rules, head) {
		struct trigger		*trigger;
		struct trigger_ip	ip;
		bool			found = false;
		char			ipbuf[INET6_ADDRSTRLEN];

		for (size_t i = 0; i < rule->num_matches && !found; ++i)
			found = match_check(&ip, &rule->matches[i],
					    strbuf_to_str(str, false));

		if (!found) {
			ldbg("not matched by rule '%s'",
				rule->name);
			continue;
		}

		BUG_ON(ip.family != AF_INET && ip.family != AF_INET6);

		ldbg("matched ip " IP_FMT " by rule '%s'",
		     IP_ARG(&ip, ipbuf), rule->name);

		if (whitelist_match(env->whitelist, env->num_whitelist, &ip)) {
			log_msg(L_INFO, DEBUG_CATEGORY,
				"ip " IP_FMT " whitelisted; skipping",
				IP_ARG(&ip, ipbuf));
			continue;
		}

		trigger = rule_trigger(rule, &ip, &now);

		if (trigger->rate.counter == 0) {
			sources_block(env, rule, trigger, &now);
		} else {
			--trigger->rate.counter;
		}
	}
}

static bool sources_handle_source(struct epoll_handler *h,
				  int epollfd, uint32_t events)
{
	struct source_handler		*shdl =
		container_of(h, struct source_handler, h);
	struct source			*s = shdl->s;
	bool				do_reopen = (events & EPOLLHUP) != 0;

	ldbg("got event %04x from source '%s'", events, s->name);

	if (events & EPOLLIN) {
		if (s->read(s)) {
			while (s->has_line(s)) {
				s->get_line(s, shdl->buf);
				sources_handle_line(h->env, s, shdl->buf);

				do_reopen = false;
			}
		} else if (errno != EAGAIN && errno != EINTR) {
			lerr("failed to read from source '%s'", s->name);
			do_reopen = true;
		}
	}

	if (do_reopen) {
		if (!s->reopen) {
			lerr("source '%s' has been closed", s->name);
			return false;
		}

		epoll_ctl(epollfd, EPOLL_CTL_DEL, s->fd, NULL);

		if (!s->reopen(s, h->env->ctx.parser->can_reopen)) {
			lerr("failed to reopen source '%s'", s->name);
			return false;
		}

		if (!sources_register_source(epollfd, shdl))
			return false;

		log_msg(L_INFO, DEBUG_CATEGORY, "source '%s' reopened", s->name);
	}

	return true;
}

static bool sources_handle_main(struct epoll_handler *h,
				int epollfd, uint32_t events)
{
	ldbg("got event %04x from main", events);

	h->env->shutdown = true;
	return true;
}

static void sources_gc(struct environment *env, int timer_fd)
{
	struct parser_context	*ctx = env->ctx.parser;
	int			out_fd = ctx->proc->fd_parser_to_filter;
	struct timespec		now;
	struct trigger		*trigger;
	struct trigger		*tmp;
	struct timespec const	*next_tm = NULL;

	xclock_gettime(&now);

	list_foreach_entry_save(trigger, tmp, &ctx->blocked_items, head) {
		char		ipbuf[INET6_ADDRSTRLEN];

		if (timespec_before(&now, &trigger->eob)) {
			next_tm = &trigger->eob;
			break;
		}

		log_msg(L_INFO, DEBUG_CATEGORY,
			"trigger " TRIGGER_FMT " reached EOB",
			TRIGGER_ARG(trigger, ipbuf));

		if (!write_all(out_fd, "-", 1) ||
		    !write_all(out_fd, trigger, sizeof *trigger)) {
			lwarn("failed to send - item to filter");
		}

		trigger_free(trigger);
	}

	if (next_tm) {
		struct itimerspec	tspec = {
			.it_value	= *next_tm,
		};
		int			rc;

		rc = timerfd_settime(timer_fd, TFD_TIMER_ABSTIME, &tspec, NULL);
		if (rc < 0)
			lwarn("timerfd_settime(): %m");
	}
}

static bool sources_handle_timer(struct epoll_handler *h,
				 int epollfd, uint32_t events)
{
	uint64_t	tmp;

	ltrace("h=%p, fd=%d, events=%04x", h, epollfd, events);

	if (read(h->fd, &tmp, sizeof tmp) < 0) {
		/* noop; this branch is to avoid -Wunused-result warnings */
	}

	sources_gc(h->env, h->fd);

	return true;
}

static bool open_sources(struct environment *env, size_t *num_sources,
			 struct source_handler **handlers,
			 struct strbuf *buf)
{
	struct source		*s;
	size_t			i;
	size_t			cnt = 0;
	struct source_handler	*hdl = NULL;
	bool			rc = false;

	ltraceA("env=%p, num_sources=%p, handlers=%p, buf=%p",
		env, num_sources, handlers, buf);

	list_foreach_entry(s, &env->sources, head) {
		if (!s->open(s)) {
			lerr("failed to open source '%s'", s->name);
			goto out;
		}

		++cnt;
	}

	hdl = Xcalloc(cnt, sizeof hdl[0]);

	i = 0;
	list_foreach_entry(s, &env->sources, head) {
		struct source_handler	*h = &hdl[i];

		h->h.fn  = sources_handle_source;
		h->h.env = env;
		h->h.fd  = s->fd;
		h->s     = s;
		h->buf   = buf;

		++i;
	}

	*num_sources = cnt;
	*handlers = hdl;

	rc = true;

out:
	ltraceD("--> %d/%zu, %p", rc, *num_sources, *handlers);

	return rc;
}

static bool drop_perm(struct environment *env)
{
	int			rc;
	struct parser_context	*ctx = env->ctx.parser;

	if (env->parser.chroot) {
		rc = chroot(env->parser.chroot);
		if (rc < 0) {
			lerr("chroot(%s): %m", env->parser.chroot);
			goto out;
		}

		ctx->can_reopen = false;
	}

	rc = chdir("/");
	if (rc < 0) {
		lerr("chdir(/): %m");
		goto out;
	}

	if (env->parser.gid != (gid_t)(-1)) {
		gid_t	gid =env->parser.gid;

		rc = setresgid(gid, gid, gid);
		if (rc < 0) {
			lerr("setresgid(%d): %m", gid);
			goto out;
		}

		ctx->can_reopen = false;
	}

	if (env->parser.uid != (uid_t)(-1)) {
		uid_t	uid =env->parser.uid;

		rc = setresuid(uid, uid, uid);
		if (rc < 0) {
			lerr("setresuid(%d): %m", uid);
			goto out;
		}

		if (uid != 0)
			ctx->can_reopen = false;
	}

	rc = 0;

out:
	return rc >= 0;
}

static int init_epoll(struct source_handler source_handlers[],
		      size_t num_sources,
		      struct epoll_handler extra_handler[], size_t num_extra)
{
	int		fd;
	int		rc = -1;

	fd = epoll_create1(EPOLL_CLOEXEC);
	if (fd < 0) {
		lerr("epoll_create1(): %m");
		goto out;
	}

	for (size_t i = 0; i < num_sources; ++i) {
		if (!sources_register_source(fd, &source_handlers[i]))
			goto out;
	}

	for (size_t i = 0; i < num_extra; ++i) {
		struct epoll_handler	*hdl = &extra_handler[i];
		struct epoll_event	ev = {
			.events		= EPOLLIN,
			.data		= { .ptr = hdl },
		};

		rc = epoll_ctl(fd, EPOLL_CTL_ADD, hdl->fd, &ev);
		if (rc < 0) {
			lerr("epoll_ctl(ADD, #%zu): %m", i);
			goto out;
		}
	}

out:
	if (rc < 0) {
		if (fd >= 0)
			close(fd);
		fd = -1;
	}

	return fd;
}

static void sigalarm_handler(int sig)
{
}

void sources_run(struct subprocess *proc, struct environment *env)
{
	enum {
		HDL_MAIN,
		HDL_TIMER
	};

	int				rc;
	struct source_handler		*source_handlers = NULL;
	size_t				num_sources = 0;
	int				epollfd = -1;
	struct strbuf			buf = INIT_STRBUF(&buf);
	struct epoll_handler		extra_handlers[] = {
		[HDL_MAIN] = {
			.fn	= sources_handle_main,
			.env	= env,
			.fd	= proc->fd_main_to_sub,
		},
		[HDL_TIMER] = {
			.fn	= sources_handle_timer,
			.env	= env,
			.fd	= xtimerfd_create(TFD_CLOEXEC | TFD_NONBLOCK),
		},
	};
	struct parser_context		ctx = {
		.blocked_items	= DECLARE_LIST(&ctx.blocked_items),
		.proc		= proc,
		.can_reopen	= true,
	};

	env->ctx.parser = &ctx;
	rc = -1;

	if (extra_handlers[HDL_TIMER].fd < 0) {
		lerr("timerfd_create(): %m");
		goto out;
	}

	signal(SIGALRM, sigalarm_handler);

	if (!open_sources(env, &num_sources, &source_handlers, &buf))
		goto out;

	epollfd = init_epoll(source_handlers, num_sources,
			     extra_handlers, ARRAY_SIZE(extra_handlers));
	if (epollfd < 0)
		goto out;

	if (!drop_perm(env) ||
	    !subprocess_block_signals())
		goto out;

	ldbg("initialization complete");

	/* signal "initialization complete" */
	write_all(proc->fd_sub_to_main, "I", 1);

	while (!env->shutdown) {
		struct epoll_event	events[10];
		size_t			nfds;

		rc = epoll_wait(epollfd, events, ARRAY_SIZE(events), -1);
		if (rc >= 0) {
			nfds = rc;
		} else if (errno == EINTR) {
			continue;
		} else {
			lerr("epoll_wait(): %m");
			goto out;
		}

		for (size_t i = 0; i < nfds; ++i) {
			struct epoll_handler	*h = events[i].data.ptr;

			if (!h->fn(h, epollfd, events[i].events)) {
				rc = -1;
				goto out;
			}
		}

		sources_gc(env, extra_handlers[HDL_TIMER].fd);
	}

	rc = 0;

out:
	strbuf_destroy(&buf);
	free(source_handlers);
	xclose(&extra_handlers[1].fd);
	xclose(&proc->fd_sub_to_main);
	xclose(&proc->fd_main_to_sub);
	xclose(&proc->fd_parser_to_filter);
	xclose(&epollfd);
	environment_free(env);

	_exit(rc >= 0 ? 0 : 1);
}
