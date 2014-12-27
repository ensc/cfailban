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

#include <sys/wait.h>

#include <ensc-lib/io.h>

#include "failban.h"
#include "logging.h"
#include "rules.h"

#define DEBUG_CATEGORY	2

static void call_iptables(struct environment *env,
			  struct trigger const *trigger,
			  char const *op)
{
	struct trigger_ip const	*ip = &trigger->ip;
	char			ipbuf[INET6_ADDRSTRLEN];
	pid_t			pid;

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
		int	rc;
		int	status;

	again:
		rc = waitpid(pid, &status, 0);
		if (rc == pid) {
			/* noop */
		} else if (rc > 0) {
			lwarn("waitpid(): unexpected result %d vs %d", rc, pid);
			rc = -1;
		} else if (errno == EINTR) {
			goto again;
		} else {
			lerr("waitpid(): %m");
		}
	}

out:
	return;
}
	

static void block_ip(struct environment *env, struct trigger const *trigger)
{
	call_iptables(env, trigger, "-A");
}

static void unblock_ip(struct environment *env, struct trigger const *trigger)
{
	call_iptables(env, trigger, "-D");
}

void filter_run(struct subprocess *proc, struct environment *env)
{
	int		rc = -1;

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
		
		struct pollfd	fds[] = {
			[0] = {
				.fd	= proc->fd_parser_to_filter,
				.events	= POLLIN,
			},
			[1] = {
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

		if (fds[1].revents) {
			ldbg("got event %04x from main",
				fds[1].revents);

			env->shutdown = true;
		}

		if (fds[0].revents & POLLIN) {
			char			op;
			struct trigger		trigger;
			
			ldbg("got event %04x from parser", fds[0].revents);

			if (!read_all(fds[0].fd, &op, sizeof op) ||
			    !read_all(fds[0].fd, &trigger, sizeof trigger)) {
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
		}

	}

	rc = 0;

out:
	environment_free(env);

	_exit(rc >= 0 ? 0 : 1);
}
