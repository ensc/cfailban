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

#include "source-generic.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <ensc-lib/strbuf.h>

#include "logging.h"

#define DEBUG_CATEGORY		3

static void source_generic_selfcheck(struct source_generic const *sg)
{
	size_t const	sz = ARRAY_SIZE(sg->buf);
	bool const	wrap = sg->r_pos + sg->r_len >= sz;

	BUG_ON(sg->r_pos >= sz);
	BUG_ON(sg->r_len  > sz);

	if (sg->eol_pos != sz) {
		BUG_ON(sg->buf[sg->eol_pos] != '\n');

		BUG_ON(!wrap && sg->eol_pos  < sg->r_pos);
		BUG_ON(!wrap && sg->eol_pos >= sg->r_pos + sg->r_len);
		BUG_ON(wrap  &&
		       sg->eol_pos  < sg->r_pos &&
		       sg->eol_pos >= sg->r_pos + sg->r_len % sz);
	}
}

static bool source_generic_flush(struct source *s)
{
	struct source_generic	*sg = container_of(s, struct source_generic, s);

	source_generic_selfcheck(sg);

	sg->r_len = 0;
	sg->r_pos = 0;
	sg->eol_pos = ARRAY_SIZE(sg->buf);

	source_generic_selfcheck(sg);

	return true;
}

static void source_generic_refresh_eol_pos(struct source_generic *sg,
					   size_t pos)
{
	unsigned char const	*ptr = NULL;
	size_t			end_pos;
	bool			is_wrap;

	ltraceA("sg=" SOURCE_GENERIC_FMT ", pos=%zu",
		SOURCE_GENERIC_ARG(sg), pos);

	source_generic_selfcheck(sg);

	if (sg->r_len == 0) {
		sg->eol_pos = ARRAY_SIZE(sg->buf);
		sg->r_pos = 0;
		goto out;
	}

	if (sg->eol_pos != ARRAY_SIZE(sg->buf))
		goto out;

	if (pos == ARRAY_SIZE(sg->buf))
		pos = sg->r_pos;

	end_pos = (sg->r_pos + sg->r_len) % ARRAY_SIZE(sg->buf);
	is_wrap = (sg->r_pos + sg->r_len) >= ARRAY_SIZE(sg->buf);

	BUG_ON(is_wrap && end_pos > sg->r_pos);

	if (pos >= sg->r_pos && is_wrap) {
		size_t		l = ARRAY_SIZE(sg->buf) - pos;

		ptr = memchr(sg->buf + pos, '\n', l);

		if (!ptr)
			pos = 0;
	}

	BUG_ON(!ptr && pos > end_pos);

	if (!ptr) {
		size_t		l = end_pos - pos;

		ptr = memchr(sg->buf + pos, '\n', l);
	}

	if (!ptr)
		sg->eol_pos = ARRAY_SIZE(sg->buf);
	else
		sg->eol_pos = ptr - sg->buf;

out:
	source_generic_selfcheck(sg);

	ltraceD("--> " SOURCE_GENERIC_FMT, SOURCE_GENERIC_ARG(sg));
}

static bool source_generic_read(struct source *s)
{
	struct source_generic	*sg = container_of(s, struct source_generic, s);
	ssize_t			l;
	size_t			r_pos;
	size_t			r_len;

	ltraceA("s=" SOURCE_GENERIC_FMT, SOURCE_GENERIC_ARG(sg));

	source_generic_selfcheck(sg);

	if (sg->r_len >= ARRAY_SIZE(sg->buf)) {
		/* when buffer is full, let read() succeed iff buffer contains
		 * an eol */
		l = (sg->eol_pos == ARRAY_SIZE(sg->buf)) ? -1 : 0;
		goto out;
	}

	if (sg->r_pos + sg->r_len < ARRAY_SIZE(sg->buf)) {
		r_pos = sg->r_pos;
		r_len = ARRAY_SIZE(sg->buf) - (sg->r_pos + sg->r_len);
	} else {
		r_pos = (sg->r_pos + sg->r_len) % ARRAY_SIZE(sg->buf);
		r_len = ARRAY_SIZE(sg->buf) - sg->r_len;
	}

	l = read(sg->s.fd, sg->buf + r_pos, r_len);

	ldbg("read(%d, %zu, %zu) -> %zd", sg->s.fd, r_pos, r_len, l);

	if (l > 0) {
		sg->r_len += l;
		source_generic_refresh_eol_pos(sg, r_pos);
	} else if (l == 0) {
		lwarn("remote site closed other end of source '%s'", sg->s.name);
		goto out;
	} else if (errno == EAGAIN || errno == EINTR) {
		/* noop */
	} else {
		lwarn("read(source '%s'): %s", sg->s.name, strerror(errno));
		goto out;
	}

out:
	source_generic_selfcheck(sg);

	ltraceD("--> %zd, " SOURCE_GENERIC_FMT, l, SOURCE_GENERIC_ARG(sg));

	return l > 0;
}

static bool source_generic_has_line(struct source const *s)
{
	struct source_generic const	*sg =
		container_of(s, struct source_generic const, s);

	return sg->eol_pos < ARRAY_SIZE(sg->buf);
}

static void source_generic_get_line(struct source *s, struct strbuf *line)
{
	struct source_generic		*sg =
		container_of(s, struct source_generic, s);
	size_t				eol_pos;

	ltraceA("s=" SOURCE_GENERIC_FMT ", p=%p", SOURCE_GENERIC_ARG(sg), line);
	
	source_generic_selfcheck(sg);

	strbuf_clear(line);

	if (sg->eol_pos < sg->r_pos) {
		/* case 1: line wraps at end of ring buffer */
		size_t		l = ARRAY_SIZE(sg->buf) - sg->r_pos;

		strbuf_append_buf(line, sg->buf + sg->r_pos, l);

		sg->r_pos    = 0;
		sg->r_len   -= l;
	}

	BUG_ON(sg->eol_pos < sg->r_pos);
	BUG_ON(sg->eol_pos > sg->r_pos + sg->r_len);

	{
		size_t		l = sg->eol_pos - sg->r_pos + 1;

		strbuf_append_buf(line, sg->buf + sg->r_pos, l);

		sg->r_pos   += l;
		sg->r_pos   %= ARRAY_SIZE(sg->buf);
		sg->r_len   -= l;
	}

	eol_pos = (sg->eol_pos + 1) % ARRAY_SIZE(sg->buf);
	sg->eol_pos = ARRAY_SIZE(sg->buf);

	source_generic_refresh_eol_pos(sg, eol_pos);

	eol_pos = line->len;
	while (eol_pos > 0 &&
	       (line->b[eol_pos-1] == '\r' || line->b[eol_pos-1] == '\n'))
		--eol_pos;
	line->len = eol_pos;

	ltraceD("--> " SOURCE_GENERIC_FMT, SOURCE_GENERIC_ARG(sg));
}

void source_generic_init(struct source_generic *sg,
			 bool (*open)(struct source *),
			 void (*free)(struct source *))
{
	sg->s.fd = -1;
	sg->s.open = open;
	sg->s.free = free;

	sg->s.read = source_generic_read;
	sg->s.has_line = source_generic_has_line;
	sg->s.get_line = source_generic_get_line;
	sg->s.flush = source_generic_flush;

	sg->eol_pos = ARRAY_SIZE(sg->buf);

	source_generic_selfcheck(sg);
}

void source_generic_destroy(struct source_generic *sg)
{
	if (sg->s.fd != -1)
		close(sg->s.fd);

	freec(sg->s.name);
}

bool source_generic_open(struct source_generic *sg, int fd)
{
	if (sg->s.fd != -1)
		close(sg->s.fd);

	sg->s.fd = fd;

	source_generic_flush(&sg->s);

	return true;
}
