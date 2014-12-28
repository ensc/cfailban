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

#ifndef H_SIMPLEBAN_SRC_CONFIGURATION_H
#define H_SIMPLEBAN_SRC_CONFIGURATION_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

struct ip_whitelist;
struct environment;
struct _dictionary_;
struct list_head;

bool configuration_parse_rules(struct _dictionary_ *dict,
			       struct list_head *rules);

bool configuration_parse_sources(struct _dictionary_ *dict,
				 struct list_head *rules);

bool configuration_parse_whitelist(struct _dictionary_ *dict,
				   struct ip_whitelist **wlist,
				   size_t *num_wlist);

bool configuration_parse_filter(struct _dictionary_ *dict,
				struct environment *env);

char const *configuration_lookup_placeholder(char const *str, size_t len);

bool configuration_get_string(char const **res, struct _dictionary_ *dict,
			      char *base, char const *key);

bool configuration_get_uint(unsigned int *res, struct _dictionary_ *dict,
			    char *base, char const *key);

bool configuration_get_rate(uint64_t *res, struct _dictionary_ *dict,
			    char *base, char const *key);


#endif	/* H_SIMPLEBAN_SRC_CONFIGURATION_H */
