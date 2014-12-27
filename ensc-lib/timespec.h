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

#ifndef H_ENSC_LIB_TIMESPEC_H
#define H_ENSC_LIB_TIMESPEC_H

#include <stdint.h>

inline static uint64_t timespec_to_ns(struct timespec const *ts)
{
	uint64_t	ts_ns = ts->tv_sec;

	ts_ns *= 1000000000ull;
	ts_ns += ts->tv_nsec;

	return ts_ns;
}

inline static int64_t timespec_delta_ns(struct timespec const *a,
					struct timespec const *b)
{
	uint64_t	a_ns = timespec_to_ns(a);
	uint64_t	b_ns = timespec_to_ns(b);

	if (a_ns >= b_ns)
		return a_ns - b_ns;
	else
		return -(b_ns - a_ns);
}

inline static void timespec_add_ns(struct timespec *ts, uint64_t ns)
{
	uint64_t	ts_ns = timespec_to_ns(ts);

	ts_ns += ns;

	ts->tv_sec  = ts_ns / 1000000000ull;
	ts->tv_nsec = ts_ns % 1000000000ull;
}

inline static bool timespec_before(struct timespec const *a,
				   struct timespec const *b)
{
	if (a->tv_sec < b->tv_sec)
		return true;
	else if (b->tv_sec < a->tv_sec)
		return false;
	else
		return a->tv_nsec < b->tv_nsec;
}

#endif	/* H_ENSC_LIB_TIMESPEC_H */
