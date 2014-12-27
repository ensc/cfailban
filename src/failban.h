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

#ifndef H_SIMPLEBAN_SRC_FAILBAN_H
#define H_SIMPLEBAN_SRC_FAILBAN_H

#include <sys/types.h>

#include <ensc-lib/list.h>

#define _initfn		__attribute__((__section__(".text.initfn")))

struct parser_context;

struct environment {
	struct list_head	rules;
	struct list_head	sources;
	struct list_head	subprocesses;

	bool			shutdown;

	struct {
		char const	*chroot;
		uid_t		uid;
		uid_t		gid;
	}			parser;

	struct {
		char const	*ip4tables_prog;
		char const	*ip6tables_prog;
		char const	*chain;
		char const	*target;
	}			filter;

	union {
		struct parser_context	*parser;
	}			ctx;
};

struct subprocess {
	struct list_head	head;
	char const		*name;
	pid_t			pid;

	int			fd_main_to_sub;
	int			fd_sub_to_main;
	int			fd_parser_to_filter;
};

struct gengetopt_args_info;

bool configuration_read(struct gengetopt_args_info const *args,
			struct environment *env);

typedef void _noreturn_	(*subprocess_run)(struct subprocess *,
					  struct environment *env);


void _noreturn_	filter_run(struct subprocess *, struct environment *env);
void _noreturn_	sources_run(struct subprocess *, struct environment *env);

void	environment_free(struct environment *env);

#endif	/* H_SIMPLEBAN_SRC_FAILBAN_H */
