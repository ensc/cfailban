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

#ifndef H_SIMPLEBAN_SRC_RULES_H
#define H_SIMPLEBAN_SRC_RULES_H

#include <stdint.h>
#include <regex.h>
#include <netinet/ip.h>

#include <ensc-lib/list.h>

#define MATCH_FAMILY_AUTO	AF_UNSPEC

struct match {
	sa_family_t		family;
	regex_t			expr;
	unsigned int		idx;
};

struct rule {
	struct list_head	head;
	char const		*name;

	size_t			num_matches;
	struct match		*matches;

	/* number of 'ns' which must pass to increment the rate counter */
	uint64_t		rate;
	unsigned int		burst;
	unsigned int		ban_duration;

	sa_family_t		ip_family;
	void			*triggers;

};

struct trigger_ip {
	sa_family_t		family;
	socklen_t		len;

	union {
		unsigned char	buf[1];
		struct in_addr	ip4;
		struct in6_addr	ip6;
	}			ip;
};

struct rate {
	unsigned int		counter;
	struct timespec		last_inc;
};

struct trigger {
	struct list_head	head;
	struct rule		*rule;
	struct trigger_ip	ip;
	struct rate		rate;
	struct timespec		eob;	/* end-of-blocking */
};

struct rule *rule_alloc(char const *name);
void rule_free(struct rule *rule);

struct trigger *rule_trigger(struct rule *rule, struct trigger_ip const *ip,
			     struct timespec const *now);

void trigger_free(struct trigger *trigger);


bool match_check(struct trigger_ip *ip,
		 struct match const *match, char const *str);

#endif	/* H_SIMPLEBAN_SRC_RULES_H */
