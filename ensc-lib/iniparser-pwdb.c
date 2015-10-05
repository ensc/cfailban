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

#include "iniparser.h"

#include <stdbool.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>

#include <pwd.h>
#include <grp.h>

#include <et/com_err.h>

#include <iniparser.h>

#include "i18n.h"
#include "compiler.h"
#include "logging.h"

static char const *_iniparser_getstring(struct _dictionary_ const *cfg,
					char const *key,
					char const *dflt)
{
	return iniparser_getstring(const_cast(struct _dictionary_ *)(cfg),
				   key,
				   const_cast(char *)(dflt));
}

static bool is_number(unsigned long *v, char const *str)
{
	char		*err;

	errno = 0;
	*v = strtoul(str, &err, 10);

	return !((*v == ULONG_MAX && errno == ERANGE) ||
		 (*err && !isspace(*err)));
}

bool _hidden_ iniparser_getuser(struct _dictionary_ const *dict,
				uid_t *uid, gid_t *gid,
				char const *key, bool is_critical)
{
	char const	*tmp = _iniparser_getstring(dict, key, NULL);
	unsigned long	res;

	if (!tmp)
		return !is_critical;

	if (strcmp(tmp, "-1") == 0) {
		res = -1;
	} else if (!is_number(&res, tmp)) {
		struct passwd	*pw;

		pw = getpwnam(tmp);
		if (!pw) {
			com_err(__func__, errno,
				N_("failed to convert '%s' (--> '%s') to user\n"),
				key, tmp);
			return false;
		}

		res = pw->pw_uid;

		if (gid)
			*gid = pw->pw_gid;
	}

	*uid = res;

	return true;
}

bool iniparser_getgroup(struct _dictionary_ const *dict, gid_t *gid,
			char const *key, bool is_critical)
{
	char const	*tmp = _iniparser_getstring(dict, key, NULL);
	unsigned long	res;

	if (!tmp)
		return !is_critical;

	if (strcmp(tmp, "-1") == 0) {
		res = -1;
	} else if (!is_number(&res, tmp)) {
		struct group	*grp;

		grp = getgrnam(tmp);
		if (!grp) {
			com_err(__func__, errno,
				N_("failed to convert '%s' (--> '%s') to group\n"),
				key, tmp);
			return false;
		}

		res = grp->gr_gid;
	}

	*gid = res;

	return true;
}
