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

#ifndef H_SIMPLEBAN_SRC_UTIL_H
#define H_SIMPLEBAN_SRC_UTIL_H

#include <unistd.h>
inline static void xclose(int *fd)
{
	if (*fd != -1) {
		close(*fd);
		*fd = -1;
	}
}

#endif	/* H_SIMPLEBAN_SRC_UTIL_H */
