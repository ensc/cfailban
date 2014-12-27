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

#ifndef H_ENSC_LIB_SOURCE_GENERIC_H
#define H_ENSC_LIB_SOURCE_GENERIC_H

#include "source.h"

#include <stdlib.h>

#ifndef MAX_LINE_SIZE
#  define MAX_LINE_SIZE		4096
#endif

struct source_generic {
	struct source		s;

	unsigned char		buf[MAX_LINE_SIZE];
	size_t			r_pos;
	size_t			r_len;

	size_t			eol_pos;
};

bool source_generic_open(struct source_generic *sg, int fd);

void source_generic_init(struct source_generic *sg,
			 bool (*open)(struct source *),
			 void (*free)(struct source *));
	
void source_generic_destroy(struct source_generic *sg);

#endif	/* H_ENSC_LIB_SOURCE_GENERIC_H */
