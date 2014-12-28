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

#ifndef SBINDIR
#  define SBINDIR	"/usr/sbin"
#endif

#include "failban.h"

#include <sysexits.h>
#include <stdlib.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/signalfd.h>

#include <et/com_err.h>

#include <ensc-lib/io.h>
#include <ensc-lib/list.h>
#include <ensc-lib/xalloc.h>

#include "failban-cmdline.h"
#include "logging.h"
#include "rules.h"
#include "source.h"
#include "util.h"

#define DEBUG_CATEGORY	1

int			_log_fd;
static unsigned int	g_debug_level = (L_INFO|L_WARN|L_ERR|L_PANIC);

void alloc_error(char const *src_func, char const *file, unsigned int line,
		 char const *alloc_func)
{
	com_err(src_func, ENOMEM, "%s:%u %s() failed", file, line, alloc_func);
	abort();
}

unsigned int _log_get_debug_level(unsigned int domain)
{
	return g_debug_level;
}

static void subprocess_init(struct subprocess *sp, char const *name)
{
	sp->name = name;
	sp->fd_main_to_sub = -1;
	sp->fd_sub_to_main = -1;
	sp->fd_parser_to_filter = -1;

	list_init(&sp->head);
}

static bool subprocess_spawn(struct subprocess *sp,
			     struct environment *env,
			     subprocess_run run_fn)
{
	int	pipe_in[2] = { -1, -1 };
	int	pipe_out[2] = { -1, -1 };
	int	rc;
	pid_t	pid;

	rc = pipe2(pipe_in, O_CLOEXEC);
	if (rc < 0) {
		lerr("pipe2(<in>): %m");
		pipe_in[0] = -1;
		pipe_in[1] = -1;
		goto out;
	}

	rc = pipe2(pipe_out, O_CLOEXEC);
	if (rc < 0) {
		lerr("pipe2(<out>): %m");
		pipe_out[0] = -1;
		pipe_out[1] = -1;
		goto out;
	}

	pid = fork();
	if (pid < 0) {
		lerr("pipe2(): %m");
		goto out;
	} else if (pid == 0) {
		struct subprocess	*p;

		list_foreach_entry(p, &env->pending, head) {
			if (p == sp)
				continue;

			close(p->fd_parser_to_filter);
		};

		/* we are the child; close communication pipes of other
		 * subprocesses */
		list_foreach_entry(p, &env->subprocesses, head) {
			close(p->fd_main_to_sub);
			close(p->fd_sub_to_main);

			BUG_ON(p->fd_parser_to_filter != -1);
		}

		sp->fd_main_to_sub = pipe_out[0];
		sp->fd_sub_to_main = pipe_in[1];

		close(pipe_out[1]);
		close(pipe_in[0]);

		ldbg("subprocesses '%s' running", sp->name);

		_log_reset();
		run_fn(sp, env);
		BUG();
	} else {
		sp->fd_main_to_sub = pipe_out[1];
		sp->fd_sub_to_main = pipe_in[0];
		sp->pid = pid;

		close(pipe_out[0]);
		close(pipe_in[1]);

		xclose(&sp->fd_parser_to_filter);

		list_move_tail(&sp->head, &env->subprocesses);
	}


out:
	if (rc < 0) {
		xclose(&pipe_in[0]);
		xclose(&pipe_in[1]);
		xclose(&pipe_out[0]);
		xclose(&pipe_out[1]);
	}

	return rc >= 0;
}

static bool subprocess_connect(int *a, int *b)
{
	int		pipe[2];
	int		rc;

	rc = pipe2(pipe, O_CLOEXEC);
	if (rc < 0) {
		lerr("pipe2(<parser->filter>): %m");
		return false;
	}

	*a = pipe[1];
	*b = pipe[0];

	return true;
}

static bool subprocess_wait_init(struct subprocess *sp)
{
	char		s;

	if (!read_all(sp->fd_sub_to_main, &s, 1)) {
		lerr("failed to wait for subprocess '%s'", sp->name);
		return false;
	}

	if (s != 'I') {
		lerr("unexpected response '\\x%02x' from subprocess '%s'",
		     s, sp->name);
		return false;
	}

	log_msg(L_INFO, DEBUG_CATEGORY, "subprocess '%s' initialized", sp->name);
	return true;
}

static void subprocess_close(struct subprocess *sp)
{
	close(sp->fd_sub_to_main);
	close(sp->fd_main_to_sub);

	sp->fd_sub_to_main = -1;
	sp->fd_main_to_sub = -1;
}

static void subprocess_wait_exit(struct subprocess *sp)
{
	pid_t		pid;
	int		status;

	for (;;) {
		pid = waitpid(sp->pid, &status, 0);
		if (pid == sp->pid)
			break;
		else if (pid > 0)
			lerr("waitpid(%s) returned for unexpected pid (%d vs. %d)",
			     sp->name, pid, sp->pid);
		else if (errno == EINTR)
			continue;
		else
			lerr("waitpid(%s): %m", sp->name);

		goto out;
	}

	log_msg(L_INFO, DEBUG_CATEGORY, "subprocess '%s' exited with %04x",
		sp->name, status);

out:
	return;
}

void environment_free(struct environment *env)
{
	ltraceA("env=%p", env);

	ldbgA("destroying rules");
	while (!list_empty(&env->rules)) {
		struct rule	*r =
			list_last_entry(&env->rules, struct rule, head);

		list_del(&r->head);
		rule_free(r);
	}
	ldbgD("rules destroyed");

	ldbgA("destroying sources");
	while (!list_empty(&env->sources)) {
		struct source	*s =
			list_last_entry(&env->sources, struct source, head);

		list_del(&s->head);
		s->free(s);
	}
	ldbgD("sources destroyed");

	free(env->whitelist);

	if (env->filter._memallocated) {
		freec(env->filter.ip4tables_prog);
		freec(env->filter.ip6tables_prog);
		freec(env->filter.chain);
		freec(env->filter.target);
	}
	
	ltraceD("-->");
}

static bool parse_args(struct environment *env,
		       int argc, char *argv[])
{
	struct gengetopt_args_info	args;
	bool				rc = false;

	if (cmdline_parser(argc, argv, &args))
		goto out;

	/* this is a little bit special; set 'is_quiet' as early as
	 * possible */
	if (args.quiet_flag)
		g_debug_level = 0;
	else if (args.debug_flag)
		g_debug_level = L_MASK_LEVELS;

	rc = configuration_read(&args, env);
	cmdline_parser_free(&args);

out:
	return rc;
}

bool subprocess_block_signals(void)
{
	sigset_t	mask;
	int		rc;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);

	rc = sigprocmask(SIG_BLOCK, &mask, NULL);
	if (rc < 0) {
		lerr("sigprocmask(): %m");
		goto out;
	}

out:
	return rc >= 0;
}


static int create_signalfd(void)
{
	sigset_t	mask;
	int		rc;

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

	rc = signalfd(-1, &mask, SFD_CLOEXEC);
	if (rc < 0) {
		lerr("signalfd(): %m");
		goto out;
	}

out:
	return rc;
}

bool whitelist_match(struct ip_whitelist const wlist[], size_t num_wlist,
		     struct trigger_ip const *ip)
{
	bool				match = false;
	
	for (size_t i = 0; i < num_wlist && !match; ++i) {
		struct ip_whitelist const	*w = &wlist[i];

		if (ip->family != w->family)
			continue;

		BUG_ON(ip->len * 8 != w->len);

		match = true;
		for (size_t j = 0; j < ip->len && match; ++j)
			match = ((ip->ip.buf[j] & w->mask.buf[j]) ==
				 (w->ip.buf[j] & w->mask.buf[j]));
	}

	return match;
}

int main(int argc, char *argv[])
{
	int				rc;
	struct environment		env = {
		.rules		= DECLARE_LIST(&env.rules),
		.sources	= DECLARE_LIST(&env.sources),
		.subprocesses	= DECLARE_LIST(&env.subprocesses),
		.pending	= DECLARE_LIST(&env.pending),

		.parser		= {
			.chroot	= NULL,
			.uid	= -1,
			.gid	= -1,
		},

		.filter		= {
			.ip4tables_prog = SBINDIR "/iptables",
			.ip6tables_prog	= SBINDIR "/ip6tables",
			.chain		= "check-banned",
			.target		= "banned",
			.manage		= true,
		},
	};
	struct subprocess		proc_filter;
	struct subprocess		proc_source;
	struct subprocess		*proc;
	int				fd_sig = -1;

	_log_fd = fileno(stderr);

	/* initialize subprocesses here to ease error handling */
	subprocess_init(&proc_filter, "filter");
	subprocess_init(&proc_source, "source");

	if (!parse_args(&env, argc, argv)) {
		rc = EX_USAGE;
		goto out;
	}

	if (!subprocess_connect(&proc_source.fd_parser_to_filter,
				&proc_filter.fd_parser_to_filter)) {
		rc = EX_OSERR;
		goto out;
	}

	list_add_tail(&proc_source.head, &env.pending);
	list_add_tail(&proc_filter.head, &env.pending);

	rc = (subprocess_spawn(&proc_filter, &env, filter_run) &&
	      subprocess_spawn(&proc_source, &env, sources_run)) ? 0 : -1;

	/* close inter-process communication pipe in the main process */
	xclose(&proc_source.fd_parser_to_filter);
	xclose(&proc_filter.fd_parser_to_filter);

	if (rc < 0) {
		lerr("failed to spawn subprocesses");
		rc = EX_OSERR;
		goto out;
	}

	fd_sig = create_signalfd();
	if (fd_sig < 0) {
		lerr("failed to create signal-fd");
		rc = EX_OSERR;
		goto out;
	}

	list_foreach_entry(proc, &env.subprocesses, head) {
		if (!subprocess_wait_init(proc))
			goto out;
	}

	for (;;) {
		struct pollfd	fds[] = {
			[0] = {
				.fd	= proc_filter.fd_sub_to_main,
				.events	= POLLIN,
			},
			[1] = {
				.fd	= proc_source.fd_sub_to_main,
				.events	= POLLIN,
			},
			[2] = {
				.fd	= fd_sig,
				.events	= POLLIN,
			},
		};

		rc = poll(fds, ARRAY_SIZE(fds), -1);
		if (rc < 0 && errno == EINTR)
			continue;

		if (rc < 0) {
			lerr("poll(): %m");
			rc = EX_OSERR;
			goto out;
		}

		if (rc > 0)
			break;
	}

	rc = EX_OK;

out:
	xclose(&fd_sig);

	ldbgA("terminating subprocesses");
	list_foreach_entry(proc, &env.subprocesses, head)
		subprocess_close(proc);

	list_foreach_entry(proc, &env.subprocesses, head)
		subprocess_wait_exit(proc);
	ldbgD("subprocesses terminated");

	environment_free(&env);

	return rc;
}
