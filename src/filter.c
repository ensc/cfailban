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

#include <stdlib.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

#include <sys/wait.h>

#include <ensc-lib/io.h>

#include "failban.h"
#include "logging.h"
#include "rules.h"
#include "util.h"

#define DEBUG_CATEGORY	2

static bool wait_for_iptables(int pid)
{
	int	status;
	int	rc;

again:
	rc = waitpid(pid, &status, 0);
	if (rc == pid &&
	    WIFEXITED(status) == 0 &&
	    WEXITSTATUS(status) == 0) {
		rc = 0;
	} else if (rc == pid) {
		lwarn("child exited with %04x", status);
		rc = -1;
	} else if (rc > 0) {
		lwarn("waitpid(): unexpected result %d vs %d", rc, pid);
		rc = -1;
	} else if (errno == EINTR) {
		goto again;
	} else {
		lerr("waitpid(): %m");
	}

	return rc >= 0;
}

static bool call_iptables(struct environment *env,
			  struct trigger const *trigger,
			  char const *op)
{
	struct trigger_ip const	*ip = &trigger->ip;
	char			ipbuf[INET6_ADDRSTRLEN];
	pid_t			pid;
	bool			res = false;

	inet_ntop(ip->family, ip->ip.buf, ipbuf, sizeof ipbuf);

	pid = fork();
	if (pid < 0) {
		lerr("fork(): %m");
		goto out;
	} else if (pid == 0) {
		bool			is_ip6 = ip->family == AF_INET6;
		char const		*argv[] = {
			is_ip6 ?
			env->filter.ip6tables_prog : env->filter.ip4tables_prog,
			op, env->filter.chain,
			"-s", ipbuf,
			"-g", env->filter.target,
			"-m", "comment",
			"--comment", trigger->rule->name,
			NULL,
		};

		execv(argv[0], (void *)argv);
		lerr("execv(): %m");
		_exit(1);
	} else {
		res = wait_for_iptables(pid);
	}

out:
	return res;
}

static void log_success(char const *op, struct trigger const *trigger)
{
	struct trigger_ip const	*ip = &trigger->ip;
	char			ipbuf[INET6_ADDRSTRLEN];
	inet_ntop(ip->family, ip->ip.buf, ipbuf, sizeof ipbuf);

	syslog(LOG_NOTICE, "rule '%s': succeeded to %s entry for %s",
	       trigger->rule->name, op, ipbuf);
}

static void log_failure(char const *op, struct trigger const *trigger)
{
	struct trigger_ip const	*ip = &trigger->ip;
	char			ipbuf[INET6_ADDRSTRLEN];
	inet_ntop(ip->family, ip->ip.buf, ipbuf, sizeof ipbuf);

	syslog(LOG_ERR, "rule '%s': failed to %s entry for %s",
	       trigger->rule->name, op, ipbuf);
}

static void block_ip(struct environment *env, struct trigger const *trigger)
{
	if (call_iptables(env, trigger, "-A"))
		log_success("add", trigger);
	else
		log_failure("add", trigger);
}

static void unblock_ip(struct environment *env, struct trigger const *trigger)
{
	if (call_iptables(env, trigger, "-D"))
		log_success("remove", trigger);
	else
		log_failure("remove", trigger);
}

static bool handle_parser(struct environment *env, struct pollfd const *pfd)
{
	char			op;
	struct trigger		trigger;
	bool			rc = false;

	if (!pfd->revents)
		return true;

	ldbg("got event %04x from parser", pfd->revents);

	if (!read_all(pfd->fd, &op, sizeof op) ||
	    !read_all(pfd->fd, &trigger, sizeof trigger)) {
		lerr("failed to read parser info");
		goto out;
	}

	switch (op) {
	case '+':
		block_ip(env, &trigger);
		break;

	case '-':
		unblock_ip(env, &trigger);
		break;

	default:
		lwarn("bad op %c from parser", op);
		break;
	}

	rc = true;

out:
	return rc;
}

static bool handle_main(struct environment *env, struct pollfd const *pfd)
{
	if (!pfd->revents)
		return true;

	ldbg("got event %04x from main", pfd->revents);

	env->shutdown = true;

	return true;

}

static bool flush_chains_prog(struct environment *env, char const *prog)
{
	pid_t			pid;
	bool			res;

	if (!prog || !prog[0])
		/* tool not configured; skipping */
		return true;

	pid = fork();
	if (pid < 0) {
		lerr("fork(): %m");
		res = false;
	} else if (pid == 0) {
		char const		*argv[] = {
			prog,
			"-F", env->filter.chain,
			NULL
		};

		execv(argv[0], (void *)argv);
		lerr("execv(): %m");
		_exit(1);
	} else {
		res = wait_for_iptables(pid);
	}

	return res;
}

static bool flush_chains(struct environment *env)
{
	if (!flush_chains_prog(env, env->filter.ip4tables_prog) ||
	    !flush_chains_prog(env, env->filter.ip6tables_prog)) {
		lerr("failed to flush chains");
		return false;
	}

	return true;
}


void filter_run(struct subprocess *proc, struct environment *env)
{
	int		rc = -1;
	enum {
		FD_PARSER,
		FD_MAIN
	};

	if (!subprocess_block_signals())
		goto out;

	if (env->filter.manage && !flush_chains(env))
		goto out;

	openlog("failban", LOG_PID, LOG_AUTHPRIV);

	ldbg("initialization complete");

	/* signal "initialization complete" */
	write_all(proc->fd_sub_to_main, "I", 1);

	while (!env->shutdown) {
		struct pollfd	fds[] = {
			[FD_PARSER] = {
				.fd	= proc->fd_parser_to_filter,
				.events	= POLLIN,
			},
			[FD_MAIN] = {
				.fd	= proc->fd_main_to_sub,
				.events	= POLLIN,
			}
		};

		rc = poll(fds, ARRAY_SIZE(fds), -1);
		if (rc < 0 && errno == EINTR)
			continue;

		if (rc < 0) {
			lerr("poll(): %m");
			goto out;
		}

		if (!handle_main(env, &fds[FD_MAIN]) ||
		    !handle_parser(env, &fds[FD_PARSER])) {
			rc = -1;
			goto out;
		}
	}

	rc = 0;

out:
	if (env->filter.manage)
		/* ignore errors here */
		flush_chains(env);
	
	xclose(&proc->fd_sub_to_main);
	xclose(&proc->fd_main_to_sub);
	xclose(&proc->fd_parser_to_filter);
	environment_free(env);

	_exit(rc >= 0 ? 0 : 1);
}
