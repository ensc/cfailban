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

#include "iniparser.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <wordexp.h>

#include <iniparser.h>
#include <et/com_err.h>

#include "i18n.h"
#include "xalloc.h"
#include "compiler.h"

static char const *_iniparser_getstring(struct _dictionary_ const *cfg,
					char const *key,
					char const *dflt)
{
	return iniparser_getstring(const_cast(struct _dictionary_ *)(cfg),
				   key,
				   const_cast(char *)(dflt));
}

_hidden_ char const *iniparser_getstring_exp(struct _dictionary_ const *cfg,
					     char const *key,
					     char const *dflt)
{
	char const	*tmp = _iniparser_getstring(cfg, key, dflt);
	int		rc;
	wordexp_t	p;
	char const	*msg;

	if (!tmp) {
		rc = -1;
		msg = N_("failed to get string");
	} else {
		rc = wordexp(tmp, &p, WRDE_NOCMD | WRDE_UNDEF);

		switch (rc) {
		case WRDE_BADCHAR:
			msg = N_("bad char");
			break;

		case WRDE_BADVAL:
			msg = N_("undefined shell variable");
			break;

		case WRDE_CMDSUB:
			msg = N_("command substitution not allowed");
			break;

		case WRDE_NOSPACE:
			msg = N_("out of memory");
			break;

		case WRDE_SYNTAX:
			msg = N_("syntax error");
			break;

		default:
			msg = N_("???");
			break;
		}
	}

	if (rc != 0) {
		com_err(__func__, 0,
			N_("failed to get '%s' (--> '%s') configuration option: %s\n"),
			key, tmp, msg);
		return NULL;
	}

	if (p.we_wordc != 1) {
		com_err(__func__, 0,
			N_("ambiguous expansion for '%s' (--> '%s'): %zu values\n"),
			key, tmp, p.we_wordc);
		tmp = NULL;
	} else {
		tmp = Xstrdup(p.we_wordv[0]);
	}

	wordfree(&p);

	return tmp;
}

static char const *create_lookup_key(char const *sec, char const *key)
{
	size_t		l0 = strlen(sec);
	size_t		l1 = strlen(key);
	char		*res = malloc(l0 + l1 + 2);

	if (res) {
		char	*p = res;

		p = mempcpy(p, sec, l0);
		*p++ = ':';
		memcpy(p, key, l1 + 1);
	};

	return res;
}

_hidden_ char const *iniparser_getsecstring(struct _dictionary_ const *cfg,
					    char const *sec,
					    char const *id,
					    char const *dflt)
{
	char const	*key = create_lookup_key(sec, id);
	char const	*res =
		key ? _iniparser_getstring(cfg, key, dflt) : dflt;

	freec(key);

	return res;;
}

_hidden_ char const *iniparser_getsecstring_exp(struct _dictionary_ const *cfg,
						char const *sec,
						char const *id,
						char const *dflt)
{
	char const	*key = create_lookup_key(sec, id);
	char const	*res =
		key ? iniparser_getstring_exp(cfg, key, dflt) : dflt;

	freec(key);

	return res;;
}

_hidden_ int iniparser_getsecboolean(struct _dictionary_ const *cfg,
				     char const *sec, char const *id,
				     int notfound)
{
	char const	*key = create_lookup_key(sec, id);
	int		res =
		key ? iniparser_getboolean(const_cast(struct _dictionary_ *)(cfg),
					   key, notfound) : notfound;

	freec(key);

	return res;
}

_hidden_ int iniparser_getsecint(struct _dictionary_ const *cfg,
			char const *sec, char const *id, int notfound)
{
	char const	*key = create_lookup_key(sec, id);
	int		res =
		key ? iniparser_getint(const_cast(struct _dictionary_ *)(cfg),
				       key, notfound) : notfound;

	freec(key);

	return res;
}

_hidden_ int iniparser_getsecint_exp(struct _dictionary_ const *cfg,
				     char const *sec, char const *id,
				     int notfound)
{
	char const	*tmp = iniparser_getsecstring_exp(cfg, sec, id, NULL);
	int		res;

	if (!tmp) {
		res = notfound;
	} else {
		char	*err;

		errno = 0;
		res = strtol(tmp, &err, 0);

		if (errno == ERANGE)
			res = notfound;
		else if (err == tmp || *err)
			res = notfound;
	}

	freec(tmp);

	return res;
}
