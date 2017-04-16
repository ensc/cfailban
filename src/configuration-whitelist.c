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

#include <assert.h>
#include <string.h>

#include <iniparser.h>

#include <ensc-lib/xalloc.h>
#include <ensc-lib/safe_calloc.h>

#include "iniparser-legacy.h"
#include "rules.h"
#include "logging.h"

#define DEBUG_CATEGORY	10

static void create_mask(uint8_t *buf, size_t cnt)
{
	while (cnt >= 8) {
		*buf++ = 0xff;
		cnt   -= 8;
	}

	if (cnt > 0)
		*buf = (0xff00u >> cnt) & 0xffu;
}

static bool parse_ip_whitelist(struct ip_whitelist *ip, char const *s)
{
	size_t		l = strlen(s);
	char const	*mask;
	char		buf[l+1];
	unsigned int	plen;
	char		*err;

	ltrace("ip=%p, s=%s", ip, s);

	mask = strchr(s, '/');

	if (mask) {
		l = mask - s;
		++mask;
	}

	if (l == 0) {
		lerr("empty ip in '%s'", s);
		return false;
	}

	memcpy(buf, s, l);
	buf[l] = '\0';

	if (inet_pton(AF_INET, buf, &ip->ip.ip4) > 0) {
		ip->family = AF_INET;
		ip->len = 32;
	} else if (inet_pton(AF_INET6, buf, &ip->ip.ip6) > 0) {
		ip->family = AF_INET6;
		ip->len = 128;
	} else {
		lerr("failed to convert ip address '%s'", buf);
		return false;
	}

	if (!mask) {
		plen = ip->len;
		err  = NULL;
	} else {
		plen = strtoul(mask, &err, 10);
	}

	if (err && *err != '\0') {
		if (inet_pton(ip->family, mask, &ip->mask.buf) <= 0) {
			lerr("failed to convert ip mask '%s'", mask);
			return false;
		}
	} else if (plen > ip->len) {
		lerr("invalid ip mask '%s'", mask);
		return false;
	} else {
		static_assert(sizeof ip->mask == sizeof ip->mask.u8,
			      "unexpected layout of 'ip->mask'");
		static_assert(sizeof ip->mask == sizeof ip->mask.buf,
			      "unexpected layout of 'ip->mask'");
		static_assert(sizeof ip->mask == sizeof ip->mask.ip6,
			      "unexpected layout of 'ip->mask'");

		memset(ip->mask.buf, 0, ip->len / 8);
		create_mask(ip->mask.u8, plen);
	}

	return true;
}

bool configuration_parse_whitelist(dictionary *dict,
				   struct ip_whitelist **wlist,
				   size_t *num_wlist)
{
	int			num_keys =
		iniparser_getsecnkeys(dict, const_cast(char *)("whitelist"));
	char			**keys =
		iniparser_getseckeys(dict, const_cast(char *)("whitelist"));
	struct ip_whitelist	*ips;
	bool			rc = false;

	ips = Xcalloc(num_keys, sizeof ips[0]);

	for (size_t i = 0; i < (size_t)num_keys; ++i) {
		char const	*s = iniparser_getstring(dict, keys[i], NULL);

		if (!parse_ip_whitelist(&ips[i], s)) {
			lerr("failed to parse whitelist entry '%s' at %s",
			     s, keys[i]);
			goto out;
		}
	}

	*wlist = xfer_ptr(ips);
	*num_wlist = num_keys;
	rc = true;

out:
	free(ips);
	free(keys);

	return rc;
}
