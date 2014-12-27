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

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include <sys/poll.h>

#include <et/com_err.h>

#include <ensc-lib/strbuf.h>

#include "../src/source.h"
#include "../src/logging.h"

int		_log_fd = 2;

void alloc_error(char const *src_func, char const *file, unsigned int line,
		 char const *alloc_func)
{
	com_err(src_func, ENOMEM, "%s:%u %s() failed", file, line, alloc_func);
	abort();
}

unsigned int _log_get_debug_level(unsigned int domain)
{
	if (getenv("VERBOSE"))
		return ~0u;
	else
		return 0;
}

int main(int argc, char *argv[])
{
	struct source_fifo_params const	params = {
		.path		= argv[1],
		.manage		= true,
		.mode		= 0600,
		.owner		= -1,
		.group		= -1,
	};

	struct source			*source;
	struct strbuf			buf = INIT_STRBUF(&buf);
	int				rc = EXIT_FAILURE;

	source = source_fifo_create(&params);
	BUG_ON(!source);

	if (argc > 2) {
		FILE	*f = fopen(argv[2], "w");

		BUG_ON(!f);
		
		fprintf(f, "%u\n", getpid());
		fclose(f);
	}
	
	if (!source->open(source)) {
		printf("ERR|open\n");
		goto out;
	}

	if (argc > 2)
		kill(getpid(), SIGSTOP);

	if (argc > 2)
		unlink(argv[2]);
	
	for (;;) {
		struct pollfd	fds[1] = {
			[0] = {
				.fd	= source->fd,
				.events	= POLLIN
			},
		};
		
		bool		res;

		poll(fds, ARRAY_SIZE(fds), -1);
		if (fds[0].revents & POLLIN) {
			res = source->read(source);

			if (!res) {
				printf("ERR|read\n");
				goto out;
			}

			while (source->has_line(source)) {
				source->get_line(source, &buf);
				printf("IN|%.*s<\n", (int)buf.len, buf.b);
			}

			continue;
		}

		if (fds[0].revents & POLLHUP)
			break;
	}

	rc = 0;

out:
	source->free(source);
	strbuf_destroy(&buf);

	return rc;	
}
