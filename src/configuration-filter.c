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

#include "configuration.h"

#include <iniparser.h>

#include <ensc-lib/xalloc.h>

#include "logging.h"
#include "failban.h"

static void read_boolean(bool *b, dictionary *dict, char const *key)
{
	*b = iniparser_getboolean(dict, key, *b);
}

static void read_string(char const **s, dictionary *dict, char const *key)
{
	char const	*res;

	res = iniparser_getstring(dict, key, const_cast(char *)(*s));
	if (res)
		res = Xstrdup(res);

	*s = res;
}

bool configuration_parse_filter(dictionary *dict,
				struct environment *env)
{
	read_string(&env->filter.ip4tables_prog, dict, "filter:ip4tables_prog");
	read_string(&env->filter.ip6tables_prog, dict, "filter:ip6tables_prog");
	read_string(&env->filter.chain, dict, "filter:chain");
	read_string(&env->filter.target, dict, "filter:target");
	read_boolean(&env->filter.manage, dict, "filter:manage");

	env->filter._memallocated = true;

	return true;
}
