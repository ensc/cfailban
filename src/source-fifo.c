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

#include "source-generic.h"

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <ensc-lib/xalloc.h>
#include <ensc-lib/safe_calloc.h>

#include "logging.h"

#define DEBUG_CATEGORY	5

struct source_fifo {
	struct source_generic		sg;
	struct source_fifo_params	params;

	bool				is_owner;
};

static bool source_fifo_open(struct source *src)
{
	struct source_fifo		*fifo =
		container_of(src, struct source_fifo, sg.s);
	int				rc;
	int				fd = -1;
	unsigned int			open_flags = 0;

	/* when we manage the fifo, unlink it first and open it with
	 * O_NOFOLLOW */
	if (fifo->params.manage) {
		unlink(fifo->params.path); /* ignore errors */

		rc = mkfifo(fifo->params.path, 0600);
		if (rc < 0) {
			lerr("mkfifo(%s): %s", fifo->params.path,
			     strerror(errno));
			goto out;
		}

		open_flags = O_NOFOLLOW;
	}

	rc = open(fifo->params.path,
		  O_RDONLY | O_NONBLOCK | O_CLOEXEC | open_flags);
	if (rc < 0) {
		lerr("open(%s): %s", fifo->params.path,
			strerror(errno));
		goto out;
	}

	fd = rc;

	fifo->is_owner = fifo->params.manage;
	if (fifo->is_owner) {
		rc = fchown(fd, fifo->params.owner, fifo->params.group);
		if (rc < 0) {
			lerr("fchown(%s): %s", fifo->params.path,
			     strerror(errno));
			goto out;
		}

		rc = fchmod(fd, fifo->params.mode);
		if (rc < 0) {
			lerr("fchmod(%s): %s", fifo->params.path,
			     strerror(errno));
			goto out;
		}
	}

	if (!source_generic_open(&fifo->sg, fd))
		goto out;

	rc = 0;

out:
	if (rc < 0) {
		if (fifo->is_owner)
			unlink(fifo->params.path);

		fifo->is_owner = false;
		if (fd >= 0)
			close(fd);
	}

	return rc >= 0;
}

static bool source_fifo_reopen(struct source *src)
{
	struct source_fifo		*fifo =
		container_of(src, struct source_fifo, sg.s);
	unsigned int			open_flags = 0;
	int				fd;

	if (fifo->params.manage)
		open_flags = O_NOFOLLOW;

	if (src->fd != -1) {
		close(src->fd);
		src->fd = -1;
	}
	
	fd = open(fifo->params.path,
		  O_RDONLY | O_NONBLOCK | O_CLOEXEC | open_flags);
	if (fd < 0) {
		lerr("open(%s): %s", fifo->params.path, strerror(errno));
		goto out;
	}

	if (!source_generic_open(&fifo->sg, fd))
		goto out;

	return true;

out:
	return false;
}

static void source_fifo_free(struct source *src)
{
	struct source_fifo		*fifo =
		container_of(src, struct source_fifo, sg.s);

	ltraceA("src(fifo)=%p[%s]", src, src->name);
		
	source_generic_destroy(&fifo->sg);

	if (fifo->is_owner)
		unlink(fifo->params.path);

	freec(fifo->params.path);
	free(fifo);

	ltraceD("-->");
}

struct source *source_fifo_create(struct source_fifo_params const *params)
{
	struct source_fifo	*res = Xcalloc(1, sizeof *res);

	res->params = *params;
	res->params.path = Xstrdup(res->params.path);

	source_generic_init(&res->sg, source_fifo_open, source_fifo_free);

	res->sg.s.reopen = source_fifo_reopen;

	return &res->sg.s;
}
