// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/filter.h>

#include "common.h"

int pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

static int pidfd_getfd(pid_t pid, int fd, unsigned int flags)
{
	return syscall(__NR_pidfd_getfd, pid, fd, flags);
}

/* Steal a network socket file descriptor from a process. Iterates
 * over all the fd's of a pid, until 16k or max_continous_gap
 * reached. For each fd checks socket family/type/protocol, for
 * matching ones validates basica address/port from sockaddr. Finally,
 * if all looks right checks socket cookie. We need to check socket
 * cookie last, since calling SO_COOKIE on a socket might mutate it
 * (generate cookie). We don't want to generate cookies really.
 * Returns a fd on success, and -1 on failure. */
int pidfd_find_socket(int pidfd, int max_continous_gap, int type, int protocol,
		      struct sockaddr_storage *addr, uint64_t cookie)
{
	int i;
	int gap = 0;
	for (i = 0; i < 16 * 1024 && gap < max_continous_gap; i++) {
		int f = pidfd_getfd(pidfd, i, 0);
		if (f < 0) {
			gap += 1;
			continue;
		}
		gap = 0;

		int r;
		int v;
		socklen_t v_sz = sizeof(v);
		r = getsockopt(f, SOL_SOCKET, SO_DOMAIN, &v, &v_sz);
		if (r != 0 || v != addr->ss_family)
			goto next;
		r = getsockopt(f, SOL_SOCKET, SO_TYPE, &v, &v_sz);
		if (r != 0 || v != type)
			goto next;
		r = getsockopt(f, SOL_SOCKET, SO_PROTOCOL, &v, &v_sz);
		if (r != 0 || v != protocol)
			goto next;

		struct sockaddr_storage ss;
		socklen_t ss_len = sizeof(ss);
		getsockname(f, (struct sockaddr *)&ss, &ss_len);

		if (ss.ss_family != addr->ss_family)
			goto next;

		switch (ss.ss_family) {
		case AF_INET: {
			struct sockaddr_in *sina = (struct sockaddr_in *)&ss;
			struct sockaddr_in *sinb = (struct sockaddr_in *)addr;
			if (sina->sin_port != sinb->sin_port)
				goto next;
			if (sina->sin_addr.s_addr != sinb->sin_addr.s_addr)
				goto next;
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *sin6a = (struct sockaddr_in6 *)&ss;
			struct sockaddr_in6 *sin6b = (struct sockaddr_in6 *)addr;
			if (sin6a->sin6_port != sin6b->sin6_port)
				goto next;
			if (memcmp(&sin6a->sin6_addr, &sin6b->sin6_addr, 16) != 0)
				goto next;
			break;
		}
		default:
			goto next;
		}

		uint64_t c;
		v_sz = sizeof(c);
		r = getsockopt(f, SOL_SOCKET, SO_COOKIE, &c, &v_sz);
		if (r != 0 || c != cookie)
			goto next;
		return (f);

	next:
		close(f);
		continue;
	}
	return -1;
}
