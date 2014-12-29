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

#include <string.h>
#include <ctype.h>
#include <limits.h>

#include <pwd.h>
#include <grp.h>

#include <iniparser.h>

#include "failban.h"
#include "logging.h"
#include "failban-cmdline.h"

#define DEBUG_CATEGORY	6

static bool tokeq(char const *str, char const *tok)
{
	size_t		l = strlen(tok);

	if (strncmp(str, tok, l) != 0)
		return false;

	if (str[l] && !isspace(str[l]))
		return false;

	return true;
}

static bool xstrneq(char const *a, size_t l, char const *b)
{
	if (strlen(b) != l)
		return false;

	if (memcmp(a, b, l) != 0)
		return false;

	return true;
}

char const *configuration_lookup_placeholder(char const *str, size_t len)
{
#define PATTERN_IP4	"([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})"
#define PATTERN_IP6	"([0-9a-fA-F:]*:([0-9a-fA-F:]*)" PATTERN_IP4 "?)"
#define PATTERN_HOST	"([0-9a-zA-Z][-0-9a-zA-Z.]+\\.[0-9a-zA-Z]+)"

	if (xstrneq(str, len, "IP4"))
		return PATTERN_IP4;
	else if (xstrneq(str, len, "IP6"))
		return PATTERN_IP6;
	else if (xstrneq(str, len, "IP"))
		return "(" PATTERN_IP4 "|" PATTERN_IP6 ")";
	else if (xstrneq(str, len, "HOST"))
		return "(" PATTERN_IP4 "|" PATTERN_IP6 "|" PATTERN_HOST ")";
	else if (xstrneq(str, len, "HOST_IP4"))
		return "(" PATTERN_IP4 "|" PATTERN_HOST ")";
	else if (xstrneq(str, len, "HOST_IP6"))
		return "(" PATTERN_IP6 "|" PATTERN_HOST ")";
	else
		return NULL;

#undef PATTERN_HOST
#undef PATTERN_IP6
#undef PATTERN_IP4
}

bool configuration_get_string(char const **res, dictionary *dict,
			      char *base, char const *key)
{
	size_t		l = strlen(base);
	char const	*str;

	strcpy(base + l, key);

	str = iniparser_getstring(dict, base, NULL);
	if (!str) {
		char		buf[sizeof("defaults:") + strlen(key)];

		strcpy(buf, "defaults:");
		strcat(buf, key);

		str = iniparser_getstring(dict, buf, NULL);
	}

	if (!str) {
		lerr("failed to read '%s' and no default defined", base);
		goto out;
	}

	*res = str;

out:
	/* reset 'base' to allow subsequent calls of parse_*() with same
	 * buffer */
	base[l] = '\0';

	return str != NULL;
}

bool configuration_get_uint(unsigned int *res, dictionary *dict,
			    char *base, char const *key)
{
	size_t		l = strlen(base);
	int		rc;

	strcpy(base + l, key);

	rc = iniparser_getint(dict, base, -1);
	if (rc < 0) {
		char		buf[sizeof("defaults:") + strlen(key)];

		strcpy(buf, "defaults:");
		strcat(buf, key);

		rc = iniparser_getint(dict, buf, -1);
	}

	if (rc < 0) {
		lerr("failed to read '%s' and no default defined", base);
		goto out;
	}

	*res = rc;
	rc = 0;

out:
	/* reset 'base' to allow subsequent calls of parse_*() with same
	 * buffer */
	base[l] = '\0';

	return rc == 0;
}

bool configuration_get_rate(uint64_t *res, dictionary *dict,
			    char *base, char const *key)
{
	char const	*rate;
	char		*err;
	char const	*unit;
	unsigned long	v;
	uint64_t	scale;
	bool		rc = false;

	if (!configuration_get_string(&rate, dict, base, key))
		goto out;

	BUG_ON(rate == NULL);

	v = strtoul(rate, &err, 10);
	if (v == ULONG_MAX || v == 0) {
		lerr("rate '%s' at %s:%s exceeds range", rate, base, key);
		goto out;
	}

	BUG_ON(!err);

	while (isspace(*err))
		++err;

	switch (*err) {
	case '/':
		unit = err+1;
		break;

	case '\0':
		unit = "min";
		break;

	default:
		lerr("invalid rate '%s' at %s:%s", rate, base, key);
		goto out;
	}

	while (isspace(*unit))
		++unit;

	scale = 0;
	if (tokeq(unit, "sec"))
		scale = 1;
	else if (tokeq(unit, "min"))
		scale = 60;
	else if (tokeq(unit, "h") || tokeq(unit, "hour"))
		scale = 3600;
	else if (tokeq(unit, "d") || tokeq(unit, "day"))
		scale = 24 * 3600;
	else
		lerr("invalid unit '%s' at %s:%s", unit, base, key);

	if (!scale)
		goto out;

	scale *= 1000000000;		/* ns */
	scale /= v;

	if (scale == 0) {
		lerr("rate '%s' too high at %s:%s", rate, base, key);
		goto out;
	}

	*res = scale;
	rc = true;

out:
	return rc;
}

bool _initfn configuration_read(struct gengetopt_args_info const *args,
				struct environment *env)
{
	dictionary	*d;
	bool		res = false;

	ltraceA("args=%p, env=%p", args, env);

	d = iniparser_load(args->config_arg);
	if (!d) {
		lerr("failed to open configuration file '%s'",
		     args->config_arg);
		goto out;
	}

	if (!configuration_parse_sources(d, &env->sources) ||
	    !configuration_parse_rules(d, &env->rules) ||
	    !configuration_parse_filter(d, env) ||
	    !configuration_parse_parser(d, env) ||
	    !configuration_parse_whitelist(d, &env->whitelist, &env->num_whitelist))
		goto out;


	res = true;

out:
	endpwent();
	endgrent();

	iniparser_freedict(d);

	ltraceD("--> %d", res);

	return res;
}
