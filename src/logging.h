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

#ifndef H_SIMPLEBAN_SRC_LOGGING_H
#define H_SIMPLEBAN_SRC_LOGGING_H

#include <inttypes.h>
#include <arpa/inet.h>
#include <ensc-lib/logging.h>

/* avoid -Waddress compiler warnings */
#define _make_ptr(_ptr) ({ __typeof__(_ptr) _tmp_ptr = (_ptr); _tmp_ptr; })

#define RULE_FMT	"%p[%s, %zu, [%" PRIu64 ", %u, %u], %d, %p]"
#define RULE_ARG(_r)				\
	(_r),					\
	((_r) ? (_r)->name : NULL),		\
	((_r) ? (_r)->num_matches : 0u),	\
	((_r) ? (_r)->rate : (uint64_t)0),	\
	((_r) ? (_r)->burst : 0u),		\
	((_r) ? (_r)->ban_duration : 0u),	\
	((_r) ? (_r)->ip_family : -1),		\
	((_r) ? (_r)->triggers : NULL)

#define IP_FMT		"%p[%d, %zu, %s]"
#define IP_ARG_(_ip, _tmpbuf)				\
	(_ip),						\
	((_ip) ? (_ip)->family : -1),			\
	((_ip) ? (size_t)((_ip)->len) : 0u),		\
	((_ip) ? inet_ntop((_ip)->family, (_ip)->ip.buf,\
			   (_tmpbuf),			\
			   __must_be_array(_tmpbuf) + sizeof(_tmpbuf)) : NULL)

#define IP_ARG(_ip, _tmpbuf)			\
	IP_ARG_(_make_ptr(_ip), _tmpbuf)

#define LIST_FMT "%p[%p, %p]"
#define LIST_ARG(_l)				\
	(_l),					\
	((_l) ? (_l)->prev : NULL),		\
	((_l) ? (_l)->next : NULL)

#define TIMESPEC_FMT	"%ld.%09lu"
#define TIMESPEC_ARG(_t)			\
	((_t) ? (long)((_t)->tv_sec) : 0l),	\
	((_t) ? (_t)->tv_nsec : 0l)		\

#define RATE_FMT	"%u, " TIMESPEC_FMT
#define RATE_ARG(_r)					\
	((_r) ? (_r)->counter : 0u),			\
	TIMESPEC_ARG((_r) ? &(_r)->last_inc : NULL)

#define TRIGGER_FMT	"%p[%p, " LIST_FMT ", [" IP_FMT "], [" RATE_FMT "], " TIMESPEC_FMT
#define TRIGGER_ARG(_t, _tmpbuf)			\
	(_t),						\
	((_t) ? (_t)->rule : NULL),			\
	LIST_ARG((_t) ? &(_t)->head : NULL),		\
	IP_ARG((_t) ? &(_t)->ip : NULL, (_tmpbuf)),	\
	RATE_ARG((_t) ? &(_t)->rate : NULL),		\
	TIMESPEC_ARG((_t) ? &(_t)->eob : NULL)

#define SOURCE_GENERIC_FMT	"%p[%zu+%zu|%zu]"
#define SOURCE_GENERIC_ARG_(_sg)		\
	(_sg),					\
	((_sg) ? (_sg)->r_pos : 0u),		\
	((_sg) ? (_sg)->r_len : 0u),		\
	((_sg) ? (_sg)->eol_pos : 0u)
#define SOURCE_GENERIC_ARG(_sg)		\
	(_sg), (_sg)->r_pos, (_sg)->r_len, (_sg)->eol_pos

#define ldbg(...)	log_msg(L_DEBUG, DEBUG_CATEGORY, ## __VA_ARGS__)
#define ldbgA(...)	log_msg(L_DEBUG|L_PUSH, DEBUG_CATEGORY, ## __VA_ARGS__)
#define ldbgD(...)	log_msg(L_DEBUG|L_POP, DEBUG_CATEGORY, ## __VA_ARGS__)
#define lwarn(...)	log_msg(L_WARN, DEBUG_CATEGORY, ## __VA_ARGS__)
#define lerr(...)	log_msg(L_ERR, DEBUG_CATEGORY, ## __VA_ARGS__)

#define ltrace(...)	log_msg(L_TRACE, DEBUG_CATEGORY, ## __VA_ARGS__)
#define ltraceA(...)	log_msg(L_TRACE|L_PUSH, DEBUG_CATEGORY, ## __VA_ARGS__)
#define ltraceD(...)	log_msg(L_TRACE|L_POP, DEBUG_CATEGORY, ## __VA_ARGS__)

#endif	/* H_SIMPLEBAN_SRC_LOGGING_H */
