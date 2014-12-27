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

#define DEBUG_CATEGORY	4

struct parser_context {
	struct list_head	blocked_items;
	struct subprocess	*proc;
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

static bool sources_register_source(int epollfd, struct source_handler *hdl)
{
	struct source		*s = hdl->s;
	struct epoll_event	ev = {
		.events		= EPOLLIN|EPOLLHUP,
		.data		= { .ptr = &hdl->h },
	};
	int			rc;

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
		int	out_fd = ctx->proc->fd_parser_to_filter;
		if (!write_all(out_fd, "+", 1) ||
		    !write_all(out_fd, trigger, sizeof *trigger)) {
			lwarn("failed to send + item to filter");
			trigger_free(trigger);
			goto out;
		}
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

	clock_gettime(CLOCK_BOOTTIME, &now);

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
		if (!s->read(s)) {
			lerr("failed to read from source '%s'", s->name);
			do_reopen = true;
		} else {
			while (s->has_line(s)) {
				s->get_line(s, shdl->buf);
				sources_handle_line(h->env, s, shdl->buf);

				do_reopen = false;
			}
		}
	}

	if (do_reopen) {
		if (!s->reopen) {
			lerr("source '%s' has been closed", s->name);
			return false;
		}

		epoll_ctl(epollfd, EPOLL_CTL_DEL, s->fd, NULL);

		if (!s->reopen(s)) {
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

	clock_gettime(CLOCK_BOOTTIME, &now);

	list_foreach_entry_save(trigger, tmp, &ctx->blocked_items, head) {
		char		ipbuf[INET6_ADDRSTRLEN];
	
		if (timespec_before(&now, &trigger->eob)) {
			next_tm = &trigger->eob;
			break;
		}

		ldbg("trigger " TRIGGER_FMT " reached EOB",
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
		bool			rc;

		rc = timerfd_settime(timer_fd, TFD_TIMER_ABSTIME,
				     &tspec, NULL);
		if (rc < 0)
			lwarn("timerfd_settime(): %m");
	}
}

static bool sources_handle_timer(struct epoll_handler *h,
				 int epollfd, uint32_t events)
{
	uint64_t	tmp;

	ltrace("h=%p, fd=%d, events=%04x", h, epollfd, events);

	(void)read(h->fd, &tmp, sizeof tmp);
	sources_gc(h->env, h->fd);

	return true;
}

void sources_run(struct subprocess *proc, struct environment *env)
{
	int				rc;
	struct source_handler		*source_handlers = NULL;
	size_t				num_sources = 0;
	int				epollfd = -1;
	struct strbuf			buf = INIT_STRBUF(&buf);
	struct epoll_handler		main_handler = {
		.fn	= sources_handle_main,
		.env	= env,
		.fd	= proc->fd_main_to_sub,
	};
	struct parser_context		ctx = {
		.blocked_items	= DECLARE_LIST(&ctx.blocked_items),
		.proc		= proc,
	};
	struct epoll_handler		timer_handler = {
		.fn	= sources_handle_timer,
		.env	= env,
	};
	
	env->ctx.parser = &ctx;

	ldbgA("opening sources");
	{
		struct source	*s;
		size_t		i;
		
		list_foreach_entry(s, &env->sources, head) {
			if (!s->open(s)) {
				log_msg(L_ERR | L_POP, 2,
					"failed to open source '%s'", s->name);
				rc = -1;
				goto out;
			}

			++num_sources;
		}

		source_handlers = Xcalloc(num_sources,
					  sizeof source_handlers[0]);

		i = 0;
		list_foreach_entry(s, &env->sources, head) {
			struct source_handler	*h = &source_handlers[i];

			h->h.fn  = sources_handle_source;
			h->h.env = env;
			h->h.fd  = s->fd;
			h->s     = s;
			h->buf   = &buf;

			++i;
		}
	}
	ldbgD("sources opened");

	epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (epollfd < 0) {
		lerr("epoll_create1(): %m");
		rc = -1;
		goto out;
	}

	for (size_t i =0; i < num_sources; ++i) {
		if (!sources_register_source(epollfd, &source_handlers[i])) {
			rc = -1;
			goto out;
		}
	}

	timer_handler.fd = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC | TFD_NONBLOCK);
	if (timer_handler.fd < 0) {
		lerr("timerfd_create(): %m");
		rc = -1;
		goto out;
	}

	{
		struct epoll_event	ev = {
			.events		= EPOLLIN,
			.data		= { .ptr = &timer_handler },
		};

		rc = epoll_ctl(epollfd, EPOLL_CTL_ADD, timer_handler.fd, &ev);
		if (rc < 0) {
			lerr("epoll_ctl(ADD, timer): %m");
			goto out;
		}
	}
	
	{
		struct epoll_event	ev = {
			.events		= EPOLLIN,
			.data		= { .ptr = &main_handler },
		};

		rc = epoll_ctl(epollfd, EPOLL_CTL_ADD, main_handler.fd, &ev);
		if (rc < 0) {
			lerr("epoll_ctl(ADD, main): %m");
			goto out;
		}
	}
	
	if (env->parser.chroot) {
		rc = chroot(env->parser.chroot);
		if (rc < 0) {
			lerr("chroot(%s): %m", env->parser.chroot);
			goto out;
		}
	}

	if (env->parser.gid != (gid_t)(-1)) {
		gid_t	gid =env->parser.gid;
		
		rc = setresgid(gid, gid, gid);
		if (rc < 0) {
			lerr("setresgid(%d): %m", gid);
			goto out;
		}
	}

	if (env->parser.uid != (uid_t)(-1)) {
		uid_t	uid =env->parser.uid;
		
		rc = setresuid(uid, uid, uid);
		if (rc < 0) {
			lerr("setresuid(%d): %m", uid);
			goto out;
		}
	}

	{
		sigset_t	mask;

		sigemptyset(&mask);
		sigaddset(&mask, SIGINT);
		sigaddset(&mask, SIGQUIT);
		sigaddset(&mask, SIGTERM);
		sigaddset(&mask, SIGHUP);

		rc = sigprocmask(SIG_BLOCK, &mask, NULL);
		if (rc < 0) {
			lerr("sigprocmask(): %m");
			goto out;
		}
	}
	
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

		sources_gc(env, timer_handler.fd);
	}
	
	rc = 0;

out:
	strbuf_destroy(&buf);
	free(source_handlers);
	environment_free(env);
	
	_exit(rc >= 0 ? 0 : 1);
}
