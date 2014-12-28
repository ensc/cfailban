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

#ifndef H_ENSC_LIB_SOURCE_H
#define H_ENSC_LIB_SOURCE_H

#include <stdbool.h>
#include <sys/types.h>

#include <ensc-lib/list.h>

struct strbuf;

struct source {
	struct list_head	head;
	char const		*name;
	int			fd;

	bool			(*open)(struct source *);
	bool			(*reopen)(struct source *, bool full_caps);
	bool			(*read)(struct source *);
	bool			(*has_line)(struct source const *);
	void			(*get_line)(struct source *, struct strbuf *line);
	void			(*free)(struct source *);
	bool			(*flush)(struct source *);

	ssize_t			(*read_ll)(struct source *, void *dst, size_t count);
};

struct source_fifo_params {
	char const		*path;
	bool			manage;
	mode_t			mode;
	uid_t			owner;
	gid_t			group;
};

struct source *source_fifo_create(struct source_fifo_params const *params);


struct source_socket_params {
	char const		*host;
	char const		*port;
	int			type;
	int			family;
};

struct source *source_fifo_create(struct source_fifo_params const *params);
struct source *source_socket_create(struct source_socket_params const *params);

#endif	/* H_ENSC_LIB_SOURCE_H */
