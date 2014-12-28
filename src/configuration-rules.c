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

#include <iniparser.h>

#include <ensc-lib/list.h>
#include <ensc-lib/xalloc.h>
#include <ensc-lib/strbuf.h>
#include <ensc-lib/safe_calloc.h>

#include "configuration.h"

#include "rules.h"
#include "failban.h"
#include "logging.h"

#define DEBUG_CATEGORY	9

struct raw_match {
	sa_family_t		family;
	char const		*pattern;
	unsigned int		idx;
};

static bool parse_match(struct raw_match *match, dictionary *dict,
			char *base, char const *suffix,
			sa_family_t sa_family)
{
	size_t	l = strlen(base);
	int	idx;

	strcpy(base + l, "pattern");
	strcat(base + l, suffix);

	match->pattern = iniparser_getstring(dict, base, NULL);
	if (!match->pattern) {
		lerr("failed to read '%s' key", base);
		return false;
	}

	strcpy(base + l, "ban");
	strcat(base + l, suffix);

	idx = iniparser_getint(dict, base, -1);
	if (idx < 0) {
		lerr("failed to read '%s' key", base);
		return false;
	}
	match->idx = idx;
	match->family = sa_family;

	ltrace("match=%p[%d, %s, %u]", match, match->family,
		match->pattern, match->idx);

	return true;
}

static bool copy_match(struct match *dst, struct raw_match const *src)
{
	int		rc = -1;
	struct strbuf	buf = INIT_STRBUF(&buf);
	char const	*p = src->pattern;
	bool		escaped = false;
	bool		placeholder = false;

	ltrace("match=%p, src=%p[%s]", dst, src, src->pattern);

	while (*p) {
		if (escaped) {
			strbuf_append_char(&buf, *p);
			escaped = false;
		} else if (placeholder) {
			char const	*end = strchr(p, '@');
			char const	*replacement;

			if (!end) {
				lerr(
					"unterminated placeholder in '%s'",
					src->pattern);
				goto out;
			}

			replacement = configuration_lookup_placeholder(p, end-p);
			if (!replacement) {
				lerr(
					"undefined placeholder '%.*s'",
					(int)(end-p), p);
				goto out;
			}

			strbuf_append_str(&buf, replacement);

			p = end;
			placeholder = false;
		} else {
			switch (*p) {
			case '\\':
				escaped = true;
				break;
			case '@':
				placeholder = true;
				break;
			default:
				strbuf_append_char(&buf, *p);
				break;
			}
		}

		++p;
	}

	ldbg("expanded: '%s'", strbuf_to_str(&buf, false));

	rc = regcomp(&dst->expr, strbuf_to_str(&buf, false), REG_EXTENDED);
	if (rc != 0) {
		size_t	l = buf.len + 256;
		char	errbuf[l];

		regerror(rc, &dst->expr, errbuf, l);

		lerr("failed to parse regexp '%s': %s",
			src->pattern, errbuf);

		goto out;
	}

	dst->idx = src->idx;
	dst->family = src->family;

	rc = 0;

out:
	strbuf_destroy(&buf);

	return rc == 0;
}

struct rule_test {
	struct list_head	head;
	char const		*name;
	char const		*test;
};

static bool test_register(struct list_head *tests, dictionary *dict,
			  char const *name, char const *key)
{
	char const		*str = iniparser_getstring(dict, key, NULL);
	struct rule_test	*res;

	if (strchr(str, '|') == NULL) {
		lerr("bad test specification '%s' in %s",
			str, key);
		return false;
	}

	res = Xcalloc(1, sizeof *res);

	res->test = str;
	res->name = name;

	list_add_tail(&res->head, tests);

	return true;
}

static bool test_run(struct rule const *rule, struct rule_test const *test)
{
	char const		*str = strchr(test->test, '|');
	char const		*exp;
	size_t			exp_len;
	bool			found = false;
	bool			failed = false;

	BUG_ON(!str);

	exp_len = str - test->test;
	++str;

	if (exp_len)
		exp = Xstrndup(test->test, exp_len);
	else
		exp = NULL;

	for (size_t i = 0; i < rule->num_matches; ++i) {
		struct trigger_ip	ip_cur;
		struct trigger_ip	ip_exp;
		struct match const	*m = &rule->matches[i];
		char			ip_buf[INET6_ADDRSTRLEN];
		int			rc;

		ldbg("running tests on match #%zu", i);
		log_push(L_DEBUG, 0);

		if (!match_check(&ip_cur, m, str)) {
			/* handle no-match tests */
			if (exp_len == 0)
				found = true;

			continue;
		}

		BUG_ON(ip_cur.family != AF_INET &&
		       ip_cur.family != AF_INET6);

		BUG_ON(ip_cur.family == AF_INET  && ip_cur.len != 32/8);
		BUG_ON(ip_cur.family == AF_INET6 && ip_cur.len != 128/8);

		inet_ntop(ip_cur.family, ip_cur.ip.buf, ip_buf, ARRAY_SIZE(ip_buf));
		ldbg("regexp matches: '%s'", ip_buf);

		if (exp_len == 0) {
			lerr("test '%s' of rule '%s' failed; found match '%s' in no-match test",
			     test->name, rule->name, ip_buf);
			failed = true;
			continue;
		}

		rc = inet_pton(ip_cur.family, exp, &ip_exp.ip.buf);
		if (rc < 1) {
			lerr("test '%s' of rule '%s' failed; can not convert expected value '%s' into ip",
			     test->name, rule->name, exp);
			failed = true;
			continue;
		}

		if (memcmp(ip_exp.ip.buf, ip_cur.ip.buf, ip_cur.len) != 0) {
			lerr("test '%s' of rule '%s' failed; unexpected match '%s' vs. '%s'",
			     test->name, rule->name, ip_buf, exp);
			failed = true;
			continue;
		}

		found = true;
	}

	if (!found) {
		lerr("test '%s' of rule '%s' failed; no results",
			test->name, rule->name);
		goto out;
	}

out:
	freec(exp);
	return found && !failed;
}

static bool run_tests(struct rule const *rule, struct list_head const *tests)
{
	struct rule_test const	*t;
	bool			failed = false;

	ltraceA("rule=" RULE_FMT ", tests=%p", RULE_ARG(rule), tests);

	list_foreach_entry(t, tests, head) {
		ltrace("test='%s'", t->name);
		log_push(L_TRACE, 0);

		if (!test_run(rule, t))
			failed = true;
	}

	if (failed) {
		lerr("testsuite of rule '%s' failed", rule->name);
		goto out;
	}

out:
	ltraceD("--> %d", !failed);

	return !failed;
}

static void free_tests(struct list_head *tests)
{
	while (!list_empty(tests)) {
		struct rule_test	*t =
			list_last_entry(tests, struct rule_test, head);

		list_del(&t->head);
		free(t);
	}
}

static bool parse_rule(dictionary *dict, struct list_head *rules,
		       char const *sec_name, char const *rule_name)
{
	int			num_keys =
		iniparser_getsecnkeys(dict, const_cast(char *)(sec_name));
	char			**keys =
		iniparser_getseckeys(dict, const_cast(char *)(sec_name));
	size_t			s_len = strlen(sec_name);
	struct rule		*rule = NULL;
	struct raw_match	*raw_matches = NULL;
	struct match		*matches = NULL;
	struct list_head	tests = DECLARE_LIST(&tests);
	size_t			num_matches = 0;
	char			name_buf[s_len + sizeof(":pattern6:duration")];
	bool			rc = false;
	bool			enabled = true;

	ltraceA("dict=%p, rules=%p, sec_name=%s, rule_name=%s",
		dict, rules, sec_name, rule_name);

	if (num_keys < 0 || !keys) {
		lerr("failed to read '%s' section", sec_name);
		goto out;
	}

	memcpy(name_buf, sec_name, s_len);
	name_buf[s_len]   = ':';

	raw_matches = Xcalloc(num_keys, sizeof raw_matches[0]);

	for (size_t i = 0; i < (size_t)num_keys; ++i) {
		char const	*key = keys[i];
		char const	*base = key + s_len + 1;
		size_t		cnt_matches = 0;

		name_buf[s_len+1] = '\0';

		ldbg("handling item '%s'", base);
		log_push(L_DEBUG, 0);

		if (strcmp(base, "pattern") == 0) {
			rc = parse_match(&raw_matches[num_matches], dict,
					 name_buf, "", 0);
			cnt_matches = 1;
		} else if (strcmp(base, "pattern4") == 0) {
			rc = parse_match(&raw_matches[num_matches], dict,
					 name_buf, "4", AF_INET);
			cnt_matches = 1;
		} else if (strcmp(base, "pattern6") == 0) {
			rc = parse_match(&raw_matches[num_matches], dict,
					 name_buf, "6", AF_INET);
			cnt_matches = 1;
		} else if (strncmp(base, "test_", 5) == 0) {
			rc = test_register(&tests, dict, base, key);
		} else if (strcmp(base, "disabled") == 0) {
			enabled = !iniparser_getboolean(dict, key, false);
		} else {
			continue;
		}

		if (!rc)
			goto out;

		num_matches += cnt_matches;
	}

	rc = false;
	ldbg("found %zu matches", num_matches);

	if (num_matches == 0) {
		lerr("no pattern in '%s' section", sec_name);
		goto out;
	}

	rule = rule_alloc(rule_name);
	if (!rule)
		goto out;

	rule->matches = Xcalloc(num_matches, sizeof matches[0]);
	for (size_t i = 0; i < num_matches; ++i) {
		if (!copy_match(&rule->matches[i], &raw_matches[i]))
			goto out;

		++rule->num_matches;
	}

	name_buf[s_len+1] = '\0';
	if (!configuration_get_rate(&rule->rate, dict, name_buf, "rate") ||
	    !configuration_get_uint(&rule->burst, dict, name_buf, "burst") ||
	    !configuration_get_uint(&rule->ban_duration, dict, name_buf, "duration"))
		goto out;

	if (!run_tests(rule, &tests))
		goto out;

	if (enabled)
		list_add_tail(&rule->head, rules);

	rc = true;

out:
	ltraceD("rc=%d, enabled=%d, rule=" RULE_FMT,
		rc, enabled, RULE_ARG(rule));

	if (!rc || !enabled) {
		rule_free(rule);
	}

	free_tests(&tests);
	free(raw_matches);
	free(keys);

	return rc;
}

bool configuration_parse_rules(dictionary *dict, struct list_head *rules)
{
	int			num_sec;
	struct list_head	new_rules = DECLARE_LIST(&new_rules);
	bool			res = false;

	num_sec = iniparser_getnsec(dict);
	if (num_sec < 0) {
		lerr("iniparser_getnsec() failed: %d", num_sec);
		goto out;
	}

	for (size_t i = 0; i < (size_t)num_sec; ++i) {
		char const	*sec_name = iniparser_getsecname(dict, i);

		if (!sec_name) {
			lerr("iniparser_getsecname(%zu) failed", i);
			goto out;
		}

		if (strncmp(sec_name, "rule/", 5) != 0)
			continue;

		if (!parse_rule(dict, &new_rules, sec_name, sec_name + 5))
			goto out;
	}

	list_splice(&new_rules, rules);
	res = true;

out:
	while (!list_empty(&new_rules)) {
		struct rule	*rule =
			list_last_entry(&new_rules, struct rule, head);

		list_del(&rule->head);
		rule_free(rule);
	}

	return res;
}
