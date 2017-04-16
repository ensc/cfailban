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

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <ensc-lib/xalloc.h>
#include <ensc-lib/safe_calloc.h>

#include "logging.h"
#include "util.h"

#define DEBUG_CATEGORY	5


enum socket_state {
	STATE_INIT,
	STATE_LISTENING,
	STATE_DATA,
	STATE_CLOSE,
};

struct source_socket {
	struct source_generic		sg;
	struct source_socket_params	params;

	int				fd_listen;
	int				fd_data;

	enum socket_state		state;
};

static bool set_state(struct source_socket *skt, int efd,
		      enum socket_state state, int xfd)
{
	struct epoll_event		ev = {
		.events		= EPOLLIN,
	};
	int				rc;

	switch (state) {
	case STATE_LISTENING:
		BUG_ON(xfd != -1 && skt->fd_listen != -1);
		BUG_ON(xfd == -1 && skt->fd_listen == -1);

		if (skt->fd_data != -1) {
			epoll_ctl(efd, EPOLL_CTL_DEL, skt->fd_data, NULL);
			xclose(&skt->fd_data);
		}

		if (xfd != -1)
			skt->fd_listen = xfd;

		ev.data.fd = skt->fd_listen;
		break;

	case STATE_DATA:
		BUG_ON(skt->fd_data != -1);

		if (skt->fd_listen != -1)
			epoll_ctl(efd, EPOLL_CTL_DEL, skt->fd_listen, NULL);

		skt->fd_data = xfd;
		ev.data.fd = xfd;
		break;

	case STATE_CLOSE:
		if (skt->fd_data != -1) {
			epoll_ctl(efd, EPOLL_CTL_DEL, skt->fd_data, NULL);
			xclose(&skt->fd_data);
		}

		if (skt->fd_listen != -1) {
			epoll_ctl(efd, EPOLL_CTL_DEL, skt->fd_listen, NULL);
			xclose(&skt->fd_listen);
		}

		ev.data.fd = -1;
		break;

	default:
		BUG();
	}

	if (ev.data.fd >= 0) {
		rc = epoll_ctl(efd, EPOLL_CTL_ADD, ev.data.fd, &ev);
		if (rc < 0) {
			lerr("epoll_ctl(ADD): %m");
			goto out;
		}
	}

	skt->state = state;
	rc = 0;

out:
	return rc >= 0;
}

static int socket_unix(struct sockaddr_un *addr, socklen_t *len,
		       struct source_socket_params const *params)
{
	size_t		l = strlen(params->host) + 1;
	if (l >= ARRAY_SIZE(addr->sun_path) * sizeof addr->sun_path[0]) {
		lerr("path '%s' too long for unix socket", params->host);
		return -1;
	}

	memset(addr, 0, sizeof *addr);
	memcpy(addr->sun_path, params->host, l);
	addr->sun_family = AF_UNIX;
	*len = offsetof(struct sockaddr_un, sun_path) + l;

	return socket(params->family,
		      params->type | SOCK_NONBLOCK  | SOCK_CLOEXEC,
		      0);
}

static int socket_inet(struct sockaddr_storage *addr, socklen_t *len,
		       struct source_socket_params const *params)
{
	struct addrinfo		hints = {
		.ai_flags	= AI_PASSIVE,
		.ai_family	= params->family,
		.ai_socktype	= params->type,
		.ai_protocol	= 0,
	};
	struct addrinfo		*res;
	int			rc;
	int			fd = -1;

	rc = getaddrinfo(params->host, params->port, &hints, &res);
	if (rc < 0) {
		lerr("getaddrinfo(%s, %s): %s", params->host, params->port,
		     gai_strerror(rc));
		goto out;
	}

	for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
		fd = socket(rp->ai_family,
			    rp->ai_socktype | SOCK_NONBLOCK  | SOCK_CLOEXEC,
			    rp->ai_protocol);

		if (fd < 0)
			continue;

		memcpy(addr, rp->ai_addr, rp->ai_addrlen);
		*len = rp->ai_addrlen;
		break;
	}

	freeaddrinfo(res);

	rc = -1;
	if (fd >= 0)
		rc = 0;
	else if (res)
		lerr("socket(): %m");
	else
		lerr("failed to resolve %s:%s", params->host, params->port);

	if (rc < 0)
		goto out;

	rc = fd;

out:
	if (rc < 0)
		xclose(&fd);

	return fd;
}

static bool source_socket_open(struct source *src)
{
	static int const		ONE = 1;

	struct source_socket		*skt =
		container_of(src, struct source_socket, sg.s);
	int				rc = -1;
	int				fd_epoll = -1;
	int				fd_listen = -1;
	union {
		struct sockaddr		generic;
		struct sockaddr_storage	storage;
		struct sockaddr_un	unx;
		struct sockaddr_in	ip4;
		struct sockaddr_in6	ip6;
	}				addr;
	socklen_t			addr_len = addr_len;


	fd_epoll = epoll_create1(EPOLL_CLOEXEC);
	if (fd_epoll < 0) {
		lerr("epoll_create1(%s): %m", src->name);
		goto out;
	}

	switch (skt->params.family) {
	case AF_UNIX:
		fd_listen = socket_unix(&addr.unx, &addr_len, &skt->params);
		break;

	case AF_UNSPEC:
	case AF_INET:
	case AF_INET6:
		fd_listen = socket_inet(&addr.storage, &addr_len, &skt->params);
		break;

	default:
		BUG();
	}

	if (fd_listen < 0) {
		lerr("failed to create listen socket for source '%s'",
		     src->name);
		goto out;
	}

	rc = setsockopt(fd_listen, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof ONE);
	if (rc < 0) {
		lerr("setsockopt(%s, <SO_REUSEADDR>): %m", src->name);
		goto out;
	}

	rc = bind(fd_listen, &addr.generic, addr_len);
	if (rc < 0) {
		lerr("bind(%s): %m", src->name);
		goto out;
	}

	switch (skt->params.type) {
	case SOCK_STREAM:
		rc = listen(fd_listen, 5);
		if (rc < 0) {
			lerr("listen(%s): %m", src->name);
			goto out;
		}

		rc = set_state(skt, fd_epoll, STATE_LISTENING, fd_listen) ? 0 : -1;
		break;

	case SOCK_DGRAM:
		rc = set_state(skt, fd_epoll, STATE_DATA, fd_listen) ? 0 : -1;
		break;

	default:
		BUG();
	}

	fd_listen = -1;

	if (rc < 0) {
		lerr("failed to set initial state of source '%s'", src->name);
		goto out;
	}

	if (!source_generic_open(&skt->sg, fd_epoll))
		goto out;

	fd_epoll = -1;
	rc = 0;

out:
	xclose(&fd_listen);
	xclose(&fd_epoll);

	if (rc < 0) {
		set_state(skt, fd_epoll, STATE_CLOSE, -1);
	}

	return rc >= 0;
}

static void source_socket_free(struct source *src)
{
	struct source_socket		*skt =
		container_of(src, struct source_socket, sg.s);

	ltraceA("src(socket)=%p[%s]", src, src->name);

	source_generic_destroy(&skt->sg);

	xclose(&skt->fd_listen);
	xclose(&skt->fd_data);

	freec(skt->params.host);
	freec(skt->params.port);
	free(skt);

	ltraceD("-->");
}

static ssize_t source_socket_read_ll(struct source *s, void *dst, size_t count)
{
	struct source_socket		*skt =
		container_of(s, struct source_socket, sg.s);
	ssize_t				rc = -1;
	int				fd;

	ltraceA("s=%p[%s, %d], %p, %zu", s, s->name, skt->state, dst, count);

	switch (skt->state) {
	case STATE_LISTENING:
		fd = accept4(skt->fd_listen, NULL, NULL,
			     SOCK_NONBLOCK | SOCK_CLOEXEC);
		rc = -1;
		if (fd >= 0) {
			if (!set_state(skt, s->fd, STATE_DATA, fd)) {
				lerr("failed to move %s into DATA state",
				     s->name);
				goto out;
			}

			errno = EAGAIN;
		} else if (errno == EAGAIN) {
			goto out;
		} else {
			lerr("accept4(%s): %m", s->name);
			goto out;
		}

		break;

	case STATE_DATA:
		rc = recv(skt->fd_data, dst, count, 0);
		if (rc == 0) {
			lwarn("remote site disconnected from source %s",
			      s->name);
			if (!set_state(skt, s->fd, STATE_LISTENING, -1)) {
				lerr("failed to move %s into LISTEN state",
				     s->name);
				goto out;
			}
		}

		break;

	default:
		BUG();
	}

out:
	ltraceD("--> %zd|%d/%d", rc, skt->state, errno);

	return rc;
}

struct source *source_socket_create(struct source_socket_params const *params)
{
	struct source_socket	*res = Xcalloc(1, sizeof *res);

	res->params = *params;
	res->params.host = Xstrdup(res->params.host);
	res->params.port = Xstrdup(res->params.port);
	res->fd_listen = -1;
	res->fd_data = -1;
	res->sg.s.read_ll = source_socket_read_ll;

	source_generic_init(&res->sg, source_socket_open, source_socket_free);

	return &res->sg.s;
}
