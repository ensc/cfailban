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

#include <errno.h>
#include <ctype.h>
#include <limits.h>

#include <pwd.h>
#include <grp.h>

#include <ensc-lib/xalloc.h>
#include <ensc-lib/iniparser.h>

#include "failban.h"
#include "source.h"
#include "logging.h"

#define DEBUG_CATEGORY		0

static bool _read_integer(int *res, dictionary *dict, char *base,
			  char const *key, bool is_critical)
{
	size_t		l = strlen(base);
	bool		rc;

	strcpy(base + l, key);
	if (is_critical)
		rc = iniparser_getstring(dict, base, NULL) != NULL;
	else
		rc = true;

	if (rc || !is_critical)
		*res = iniparser_getint(dict, base, *res);
	base[l] = '\0';

	return rc;
}

#define read_integer(_res, _dict, _base, _key, _critical)		\
	({								\
		int	_tmp = *(_res);					\
		bool	_rc = _read_integer(&_tmp, _dict, _base,	\
					    _key, _critical);		\
		if (_rc || !(_critical))				\
			*(_res) = _tmp;					\
		(_rc);							\
	})


static bool read_boolean(bool *res, dictionary *dict, char *base,
			 char const *key, bool is_critical)
{
	size_t		l = strlen(base);
	bool		rc;

	strcpy(base + l, key);
	if (is_critical)
		rc = iniparser_getstring(dict, base, NULL) != NULL;
	else
		rc = true;

	if (rc || !is_critical)
		*res = iniparser_getboolean(dict, base, *res);
	base[l] = '\0';

	return rc;
}

static bool read_string(char const **s, dictionary *dict, char *base,
			char const *key, bool is_critical)
{
	size_t		l = strlen(base);
	char const	*res;

	strcpy(base + l, key);
	res = iniparser_getstring(dict, base, NULL);
	base[l] = '\0';

	if (res || !is_critical)
		*s = res;

	return res || !is_critical;
}

static bool read_user(uid_t *uid, gid_t *gid, dictionary *dict, char *base,
		      char const *key, bool is_critical)
{
	size_t		l = strlen(base);
	bool		res;

	strcpy(base + l, key);
	res = iniparser_getuser(dict, uid, gid, base, is_critical);
	base[l] = '\0';

	return res;
}

static bool read_stype(int *proto, dictionary *dict, char *base,
		       char const *key, bool is_critical)
{
	size_t		l = strlen(base);
	char const	*tmp;
	bool		res = true;

	strcpy(base + l, key);
	tmp = iniparser_getstring(dict, base, NULL);
	base[l] = '\0';

	if (!tmp) {
		res = !is_critical;
	} else if (strcmp(tmp, "tcp") == 0 || strcmp(tmp, "stream") == 0) {
		*proto = SOCK_STREAM;
	} else if (strcmp(tmp, "udp") == 0 || strcmp(tmp, "dgram") == 0) {
		*proto = SOCK_DGRAM;
	} else {
		lerr("invalid protocol '%s' at %s:%s", tmp, base, key);
		res = false;
	}

	return res;
}

static bool read_family(int *family, dictionary *dict, char *base,
		       char const *key, bool is_critical)
{
	size_t		l = strlen(base);
	char const	*tmp;
	bool		res = true;

	strcpy(base + l, key);
	tmp = iniparser_getstring(dict, base, NULL);
	base[l] = '\0';

	if (!tmp) {
		res = !is_critical;
	} else if (strcmp(tmp, "ip") == 0 || strcmp(tmp, "ip4") == 0) {
		*family = AF_INET;
	} else if (strcmp(tmp, "ip6")) {
		*family = AF_INET6;
	} else if (strcmp(tmp, "unix") == 0 || strcmp(tmp, "local") == 0) {
		*family = AF_UNIX;
	} else {
		lerr("invalid family '%s' at %s:%s", tmp, base, key);
		res = false;
	}

	return res;
}

static bool read_group(gid_t *gid, dictionary *dict,
		       char *base, char const *key, bool is_critical)
{
	size_t		l = strlen(base);
	bool		res;

	strcpy(base + l, key);
	res = iniparser_getgroup(dict, gid, base, is_critical);
	base[l] = '\0';

	return res;
}

static struct source *_source_fifo_create(dictionary *dict, char const *sec)
{
	size_t		sec_len = strlen(sec);
	char		base[sec_len + sizeof(":manage")];
	struct source	*res = NULL;

	struct source_fifo_params	cfg = {
		.path	= "/run/failban",
		.manage	= true,
		.mode	= 0700,
		.owner	= -1,
		.group	= -1,
	};

	strcpy(base, sec);
	strcat(base, ":");

	if (!read_string(&cfg.path, dict, base, "path", true) ||
	    !read_boolean(&cfg.manage, dict, base, "manage", false) ||
	    !read_integer(&cfg.mode, dict, base, "mode", false) ||
	    !read_user(&cfg.owner, &cfg.group, dict, base, "owner", false) ||
	    !read_group(&cfg.group, dict, base, "group", false)) {
		lerr("failed to read section '%s'", sec);
		goto out;
	}

	res = source_fifo_create(&cfg);
	if (!res) {
		lerr("failed to create FIFO source object for section '%s'",
		     sec);
		goto out;
	}

	log_msg(L_INFO, DEBUG_CATEGORY,
		"created FIFO source [%s, %d, %04o, %d:%d]",
		cfg.path, cfg.manage, cfg.mode, cfg.owner, cfg.group);

out:
	return res;
}

static struct source *_source_socket_create(dictionary *dict, char const *sec)
{
	size_t		sec_len = strlen(sec);
	char		base[sec_len + sizeof(":manage")];
	struct source	*res = NULL;

	struct source_socket_params	cfg = {
		.host	= "localhost",
		.port	= "516",
		.type	= SOCK_STREAM,
		.family	= AF_UNSPEC
	};

	strcpy(base, sec);
	strcat(base, ":");

	if (!read_string(&cfg.host, dict, base, "host", true) ||
	    !read_string(&cfg.port, dict, base, "port", true) ||
	    !read_stype(&cfg.type, dict, base, "stype", false) ||
	    !read_family(&cfg.family, dict, base, "family", false)) {
		lerr("failed to read section '%s'", sec);
		goto out;
	}

	res = source_socket_create(&cfg);
	if (!res) {
		lerr("failed to create FIFO source object for section '%s'",
		     sec);
		goto out;
	}

	log_msg(L_INFO, DEBUG_CATEGORY,
		"created FIFO source [%s:%s, %d, %d]",
		cfg.host, cfg.port, cfg.type, cfg.family);

out:
	return res;
}

static struct source *
configuration_create_source(struct _dictionary_ *dict,
			    char const *sec, char const *name)
{
	size_t		sec_len = strlen(sec);
	char		base[sec_len + sizeof(":type")];
	char const	*type;
	struct source	*source = NULL;

	ltraceA("dict=%p, sec=%s, name=%s", dict, sec, name);

	strcpy(base, sec);
	strcat(base, ":type");

	type = iniparser_getstring(dict, base, NULL);
	if (!type) {
		lerr("missing 'type' attribute in section '%s", sec);
		goto out;
	}

	ldbg("type=%s", type);

	if (strcmp(type, "fifo") == 0)
		source = _source_fifo_create(dict, sec);
	else if (strcmp(type, "socket") == 0)
		source = _source_socket_create(dict, sec);
	else {
		lerr("unknown source type '%s'", type);
		goto out;
	}

	if (!source) {
		lerr("failed to create source '%s' from section '%s'",
		     name, sec);
		goto out;
	}

	BUG_ON(source->open == NULL);
	BUG_ON(source->read == NULL);
	BUG_ON(source->has_line == NULL);
	BUG_ON(source->free == NULL);

	source->name = Xstrdup(name);

out:
	ltraceD("--> %p", source);

	return source;
}

bool _initfn configuration_parse_sources(struct _dictionary_ *dict,
					 struct list_head *sources)
{
	int			num_sec;
	struct list_head	new_sources = DECLARE_LIST(&new_sources);
	bool			res = false;

	num_sec = iniparser_getnsec(dict);
	if (num_sec < 0) {
		lerr("iniparser_getnsec() failed: %d", num_sec);
		goto out;
	}

	for (size_t i = 0; i < (size_t)num_sec; ++i) {
		char const	*sec_name = iniparser_getsecname(dict, i);
		struct source	*source;

		if (!sec_name) {
			lerr("iniparser_getsecname(%zu) failed", i);
			goto out;
		}

		if (strncmp(sec_name, "source/", 5) != 0)
			continue;

		source = configuration_create_source(dict, sec_name,
						     sec_name + 7);
		if (!source)
			goto out;

		list_add_tail(&source->head, sources);
	}

	list_splice(&new_sources, sources);
	res = true;

out:
	while (!list_empty(&new_sources)) {
		struct source	*source =
			list_last_entry(&new_sources, struct source, head);

		list_del(&source->head);
		source->free(source);
	}

	return res;

}
