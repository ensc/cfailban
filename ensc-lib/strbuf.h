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

#ifndef H_ENSC_LIB_STRBUF_H
#define H_ENSC_LIB_STRBUF_H

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include "xalloc.h"

struct strbuf_const {
	char const	*b;
	size_t		len;
};

inline static void strbuf_const_assign(struct strbuf_const *buf,
				       void const *data, size_t len)
{
	buf->b = data;
	buf->len = len;
}

struct strbuf {
	size_t	len;
	size_t	alloc;
	char	*b;
};

#define INIT_STRBUF(_n) { 0, 0, NULL }

inline static void	strbuf_init(struct strbuf *buf, size_t hint)
{
	buf->b = hint ? Xrealloc(NULL, hint) : NULL;
	buf->alloc = hint;
	buf->len = 0;
}

inline static void strbuf_assign_buf(struct strbuf *buf, void *data, size_t len)
{
	buf->b = data;
	buf->len = len;
	buf->alloc = len;
}

inline static void strbuf_assign_str(struct strbuf *buf, char *str)
{
	if (!str) {
		strbuf_init(buf, 0);
	} else {
		strbuf_assign_buf(buf, str, strlen(str));
		buf->alloc += 1;
	}
}

inline static void	_strbuf_shrink(struct strbuf *buf, size_t extra)
{
	if (unlikely(buf->len > SIZE_MAX - extra))
		alloc_error(__func__, __FILE__, __LINE__, __func__);
			    
	if (buf->alloc > buf->len + extra) {
		buf->alloc = buf->len + extra;
		buf->b = Xrealloc(buf->b, buf->alloc);
	}
}

inline static void	strbuf_shrink(struct strbuf *buf)
{
	_strbuf_shrink(buf, 0);
}

inline static void	strbuf_allocate(struct strbuf *buf, size_t l)
{
	/* this is some sanity check to ensure that caller does not provide
	 * too large values for 'l'; overflow might not happen when simple
	 * 'buf->len + len' is within range, but we check it netherless.
	 *
	 * NOTE: although we check for overflows in 'l * 3/2 + 8', the '/ 2'
	 * and '+ 8' operations can be ignored because only the '* 3' can
	 * overflow for SIZE_MAX > 17 */
	if (unlikely(l > SIZE_MAX / 3))
		alloc_error(__func__, __FILE__, __LINE__, __func__);

	/* this check is critical... */
	if (unlikely(buf->len > SIZE_MAX - l))
		alloc_error(__func__, __FILE__, __LINE__, __func__);
			    
	if (buf->len + l > buf->alloc) {
		/* we checked above that this does not overflow */
		size_t		extra = l * 3 / 2 + 8;

		if (unlikely(buf->len > SIZE_MAX - extra))
			alloc_error(__func__, __FILE__, __LINE__, __func__);

		buf->alloc = buf->len + extra;
		buf->b = Xrealloc(buf->b, buf->alloc);
	}
}

inline static void *	strbuf_xfer(struct strbuf *buf, size_t *l)
{
	void	*res = buf->b;

	if (l)
		*l = buf->len;

	buf->len = 0;
	buf->alloc = 0;
	buf->b = NULL;

	return res ? res : Xmalloc(1);
}

inline static void	strbuf_destroy(struct strbuf *buf)
{
	free(buf->b);
}

inline static void	strbuf_clear(struct strbuf *buf)
{
	buf->len = 0;
}

inline static void	strbuf_append_char(struct strbuf *buf, char c)
{
	strbuf_allocate(buf, 1);

	buf->b[buf->len] = c;
	buf->len += 1;
}

inline static void	strbuf_append_buf(struct strbuf *buf,
					  void const *s, size_t l)
{
	strbuf_allocate(buf, l);

	if (l > 0) {
		memcpy(&buf->b[buf->len], s, l);
		buf->len += l;
	}
}

inline static void	strbuf_append_str(struct strbuf *buf, char const *s)
{
	strbuf_append_buf(buf, s, strlen(s));
}

inline static void	strbuf_append_strbuf(struct strbuf *buf,
					     struct strbuf const *src)
{
	strbuf_append_buf(buf, src->b, src->len);
}

inline static char const *strbuf_to_str(struct strbuf *buf, bool optimize)
{
	strbuf_allocate(buf, 1);
	buf->b[buf->len] = '\0';

	if (optimize)
		_strbuf_shrink(buf, 1);

	return buf->b;
}

#endif	/* H_ENSC_LIB_STRBUF_H */
