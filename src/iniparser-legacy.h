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

#ifndef H_SIMPLEBAN_SRC_INIPARSER_LEGACY_H
#define H_SIMPLEBAN_SRC_INIPARSER_LEGACY_H

#ifdef NO_iniparser_getsecnkeys

#include <iniparser.h>

int iniparser_getsecnkeys(dictionary * d, char * s);
char ** iniparser_getseckeys(dictionary * d, char * s);

#endif /* NO_iniparser_getsecnkeys */

#endif	/* H_SIMPLEBAN_SRC_INIPARSER_LEGACY_H */
