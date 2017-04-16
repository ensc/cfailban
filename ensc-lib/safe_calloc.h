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

#ifndef H_ENSC_LIB_SAFE_CALLOC_H
#define H_ENSC_LIB_SAFE_CALLOC_H

#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>

#include "compiler.h"
#include "type-utils.h"

inline static int _safe_calloc_check_mul(size_t a, size_t b, size_t *res)
{
	size_t	tmp;

	return !_mul_overflow(a, b, res ? res : &tmp);
}

inline static int _safe_calloc_check_add(size_t a, size_t b, size_t *res)
{
	size_t	tmp;

	return !_add_overflow(a, b, res ? res : &tmp);
}

inline static void *safe_calloc(size_t num, size_t sz)
{
	int	have_safe_calloc;

#ifdef HAVE_SAFE_CALLOC
	have_safe_calloc = 1;
#else
	have_safe_calloc = 0;
#endif

	if (!have_safe_calloc && !_safe_calloc_check_mul(num, sz, NULL)) {
		errno = ENOMEM;
		return NULL;
	}

	return calloc(num, sz);
}

inline static void *recalloc(void *old, size_t num, size_t sz)
{
	size_t	tot_sz;

	if (!_safe_calloc_check_mul(num, sz, &tot_sz)) {
		errno = ENOMEM;
		return NULL;
	}

	return realloc(old, tot_sz);
}

inline static int _sizeof_flexarr(
	size_t *res, size_t sz0, size_t cnt, size_t sz1)
{
	size_t		sz_flex;

	BUG_ON(sz0 == 0);
	BUG_ON(sz1 == 0);

	if (!_safe_calloc_check_mul(sz1, cnt, &sz_flex) ||
	    !_safe_calloc_check_add(sz0, sz_flex, res))
		return 0;

	return 1;
}

#define sizeof_flexarr(_res, _s, _n, _attr)			\
	_sizeof_flexarr(_res, sizeof(_s), _n, sizeof(_s)._attr[0])

inline static void *_malloc_flexarr(size_t sz0, size_t cnt, size_t sz1)
{
	size_t	sz;

	if (!_sizeof_flexarr(&sz, sz0, cnt, sz1)) {
		errno = ENOMEM;
		return NULL;
	}

	return malloc(sz);
}

#define malloc_flexarr(_s, _n, _attr) \
	_malloc_flexarr(sizeof*(_s), _n, sizeof((_s)->_attr[0]))

inline static void *_zalloc_flexarr(size_t sz0, size_t cnt, size_t sz1)
{
	size_t	sz;

	if (!_sizeof_flexarr(&sz, sz0, cnt, sz1)) {
		errno = ENOMEM;
		return NULL;
	}

	return calloc(1, sz);
}

#define zalloc_flexarr(_s, _n, _attr) \
	_zalloc_flexarr(sizeof*(_s), _n, sizeof((_s)->_attr[0]))

inline static void *_realloc_flexarr(void *p, size_t sz0, size_t cnt, size_t sz1)
{
	size_t	sz;

	if (!_sizeof_flexarr(&sz, sz0, cnt, sz1)) {
		errno = ENOMEM;
		return NULL;
	}

	return realloc(p, sz);
}

#define realloc_flexarr(_s, _n, _attr)			\
	_realloc_flexarr(_s, sizeof*(_s), _n, sizeof((_s)->_attr[0]))

#endif	/* H_ENSC_LIB_SAFE_CALLOC_H */
