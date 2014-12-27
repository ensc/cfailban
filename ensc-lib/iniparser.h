/*	--*- c -*--
 * Copyright (C) 2013 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
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

#ifndef H_ENSC_LIB_INIPARSER_H
#define H_ENSC_LIB_INIPARSER_H

#include <stdbool.h>
#include <sys/types.h>

struct _dictionary_;
char const *iniparser_getstring_exp(struct _dictionary_ *cfg,
				    char const *key,
				    char const *dflt);

bool iniparser_getuser(struct _dictionary_ *cfg, uid_t *uid, gid_t *gid,
		       char const *key, bool is_critical);

bool iniparser_getgroup(struct _dictionary_ *cfg, gid_t *gid,
			char const *key, bool is_critical);

#endif	/* H_ENSC_LIB_INIPARSER_H */
