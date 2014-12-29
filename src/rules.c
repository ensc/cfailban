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

#include "rules.h"

#include <string.h>
#include <stdlib.h>
#include <search.h>
#include <netdb.h>
#include <sys/time.h>

#include <ensc-lib/safe_calloc.h>
#include <ensc-lib/xalloc.h>
#include <ensc-lib/timespec.h>

#include "logging.h"

#define DEBUG_CATEGORY	8

static int trigger_compare(void const *a_, void const *b_)
{
	struct trigger const	*a = a_;
	struct trigger const	*b = b_;
	int			d;

	if (a->ip.family < b->ip.family) {
		d = -1;
	} else if (a->ip.family > b->ip.family) {
		d = +1;
	} else {
		BUG_ON(a->ip.len != b->ip.len);
		d = memcmp(&a->ip.ip, &b->ip.ip, a->ip.len);
	}

	return d;
}

static void _trigger_free(void *t)
{
	char		tmpbuf[INET6_ADDRSTRLEN];
	struct trigger	*trigger = t;

	BUG_ON(!trigger);

	log_msg(L_ALLOC, DEBUG_CATEGORY, "trigger = " TRIGGER_FMT,
		TRIGGER_ARG(trigger, tmpbuf));

	list_del(&trigger->head);
	free(t);
}

void trigger_free(struct trigger *trigger)
{
	if (!trigger)
		return;

	tdelete(trigger, &trigger->rule->triggers, trigger_compare);
	_trigger_free(trigger);
}

struct trigger *rule_trigger(struct rule *rule, struct trigger_ip const *ip,
			     struct timespec const *now)
{
	char			tmpbuf[INET6_ADDRSTRLEN];
	struct trigger		tmp = {
		.ip	= *ip,
		.rule	= rule,
		.rate	= {
			.counter = rule->burst,
			.last_inc = *now,
		}
	};
	struct trigger		*res;
	struct trigger		**item;
	int64_t			delta;

	ltraceA("rule=" RULE_FMT ", ip=" IP_FMT ", now=" TIMESPEC_FMT,
		RULE_ARG(rule), IP_ARG(ip, tmpbuf), TIMESPEC_ARG(now));

	/* will cause division-by-zero below else */
	BUG_ON(rule->rate == 0);

	/* to avoid an unnessary memory allocation, search for the ip twice.
	 * In the first run, just look for it and when not found, allocate
	 * memory and insert it */
	item = tfind(&tmp, &rule->triggers, trigger_compare);
	if (!item) {
		struct trigger	*new_trigger = Xmalloc(sizeof *new_trigger);

		ldbg("rule not triggered by ip yet; creating new entry");

		*new_trigger = tmp;

		item = tsearch(new_trigger, &rule->triggers, trigger_compare);
		if (!item) {
			free(new_trigger);
			alloc_error(__func__, __FILE__, __LINE__, "tsearch");
		}

		/* as tfind() returned NULL, a new entry was added and it is
		 * expected that tsearch() returns the key */
		BUG_ON(*item != new_trigger);

		list_init(&new_trigger->head);
	}

	res = *item;

	BUG_ON(res == NULL);
	BUG_ON(res->rule != rule);

	delta = timespec_delta_ns(now, &res->rate.last_inc);
	if (delta < 0) {
		/* this should not happen...  */
		lwarn("unexpected internal event 'delta < 0'");
		res->rate.counter = 0;
	} else {
		uint64_t	new_cnt = delta / rule->rate;

		ldbg("new_cnt=%" PRIu64 ", delta=%" PRIu64,
			new_cnt, delta);

		/* clamp new rate not to exceed burst rate */
		if (res->rate.counter > rule->burst ||
		    new_cnt > rule->burst - res->rate.counter)
			res->rate.counter  = rule->burst;
		else
			res->rate.counter += new_cnt;

		/* update the last-inc timestamp */
		timespec_add_ns(&res->rate.last_inc, new_cnt * rule->rate);
	}

	ltraceD("res = " TRIGGER_FMT, TRIGGER_ARG(res, tmpbuf));

	return res;
}

struct rule *rule_alloc(char const *name)
{
	struct rule *res;

	ltrace("name=%s", name);

	res = Xcalloc(1, sizeof *res);
	res->name = Xstrdup(name);

	return res;
}

void rule_free(struct rule *rule)
{
	log_msg(L_ALLOC, DEBUG_CATEGORY, "rule = " RULE_FMT, RULE_ARG(rule));
	log_push(L_ALLOC, DEBUG_CATEGORY);

	if (!rule)
		return;

	tdestroy(rule->triggers, _trigger_free);

	for (size_t i = 0; i < rule->num_matches; ++i)
		regfree(&rule->matches[i].expr);

	free(rule->matches);
	freec(rule->name);
	free(rule);
}

static bool match_lookup(struct trigger_ip *ip,
			 struct match const *match,
			 char *str)
{
	int		rc;

	/* try to resolve it with cheap functions first */
	switch (match->family) {
	case AF_UNSPEC:
		ip->family = AF_INET;
		rc = inet_pton(ip->family, str, &ip->ip.ip4);
		if (rc < 1) {
			ip->family = AF_INET6;
			rc = inet_pton(ip->family, str, &ip->ip.ip6);
		}

		break;

	case AF_INET:
	case AF_INET6:
		ip->family = match->family;
		rc = inet_pton(ip->family, str, &ip->ip.buf);
		break;

	default:
		BUG();
	}

	if (rc < 1 && match->do_resolve) {
		struct addrinfo	const	hint = {
			.ai_family	= match->family,
			/* request TCP addresses only to prevent duplicate
			 * results */
			.ai_socktype	= SOCK_STREAM,
			.ai_protocol	= 6,
		};
		struct addrinfo		*result;
		struct itimerval	itimer = {
			.it_value = {
				.tv_sec		= 1,
				.tv_usec	= 500000,
			},
		};
		size_t			l = strlen(str);

		/* append a '.' to prevent iterating the DNS search list;
		 * caller has to ensure that buffer is large enough */
		if (l > 0 && str[l-1] != '.')
			strcpy(str + l, ".");

		rc = setitimer(ITIMER_REAL, &itimer, NULL);
		if (rc < 0) {
			lerr("setitimer(): %m");
			goto out;
		}
		rc = getaddrinfo(str, NULL, &hint, &result);

		/* stop timer; TODO: read error? */
		memset(&itimer, 0, sizeof itimer);
		setitimer(ITIMER_REAL, &itimer, NULL);
		
		if (rc) {
			lerr("getaddrinfo(%s): %s", str, gai_strerror(rc));
			result = NULL;
		} else if (!result) {
			lwarn("getaddrinfo(%s) returned no result", str);
			rc = -1;
		} else if (result->ai_next) {
			lwarn("getaddrinfo(%s) returned multiple results", str);
			rc = -1;
		} else {
			union {
				struct sockaddr_storage		storage;
				struct sockaddr			generic;
				struct sockaddr_in		ip4;
				struct sockaddr_in6		ip6;
			} const			*addr;

			addr = (void const *)result->ai_addr;

			ip->family = result->ai_family;

			switch (ip->family) {
			case AF_INET:
				ip->ip.ip4 = addr->ip4.sin_addr;
				break;

			case AF_INET6:
				ip->ip.ip6 = addr->ip6.sin6_addr;
				break;

			default:
				BUG();
			}

			rc = 1;
		}

		freeaddrinfo(result);
	}

	if (rc > 0) {
		switch (ip->family) {
		case AF_INET:	ip->len = 32/8; break;
		case AF_INET6:	ip->len = 128/8; break;
		default:	BUG();
		}
	}

out:
	return rc > 0;
}

bool match_check(struct trigger_ip *ip,
		 struct match const *match, char const *str)
{
	regoff_t		rm_eo;
	regoff_t		rm_so;
	int			rc;
	/* RFC 1035 specifies a DNS name limit of 256 chars */
	char			ip_buf[256 + 16 + 64];
	regmatch_t		cur_matches[match->idx + 1];

	rc = regexec(&match->expr, str, match->idx + 1, cur_matches,
		     REG_EXTENDED);
	if (rc != 0) {
		ldbg("expression does not match");
		return false;
	}

	rm_so = cur_matches[match->idx].rm_so;
	rm_eo = cur_matches[match->idx].rm_eo;

	if (rm_so == -1 || rm_eo == -1) {
		ldbg("expression matches but not group %u",
			match->idx);
		return false;
	}

	BUG_ON(rm_eo < rm_so);

	/* reserve space for for trailing '\0' and perhaps a '.' */
	if ((size_t)(rm_eo - rm_so) >= sizeof ip_buf - 2u) {
		lerr("match '%.*s' in '%s' exceeds internal buffers",
		     (int)(rm_eo - rm_so), str + rm_so, str);
		return false;
	}

	memcpy(ip_buf, str + rm_so, rm_eo - rm_so);
	ip_buf[rm_eo - rm_so] = '\0';

	ldbg("match returned '%s'", ip_buf);

	memset(ip, 0, sizeof *ip);

	rc = match_lookup(ip, match, ip_buf) ? 0 : -1;
	if (rc < 0) {
		lwarn("failed to convert '%s' into ip (%d family)",
		      ip_buf, match->family);
		return false;
	}

	return true;
}
