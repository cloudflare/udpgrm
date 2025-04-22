#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include "common.h"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

socklen_t net_ss_size(struct sockaddr_storage *ss)
{
	switch (ss->ss_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	case AF_UNIX: {
		struct sockaddr_un *sun = (struct sockaddr_un *)(ss);
		socklen_t l = __builtin_offsetof(struct sockaddr_un, sun_path);
		if (sun->sun_path[0] != '\x00') {
			l += strnlen(sun->sun_path, UNIX_PATH_MAX);
		} else {
			l += 1 + strnlen(&sun->sun_path[1], UNIX_PATH_MAX - 1);
		}
		return l;
	}
	}
	return sizeof(struct sockaddr_storage);
}

int net_get_port(struct sockaddr_storage *ss)
{
	switch (ss->ss_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)ss;
		return ntohs(sin->sin_port);
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
		return ntohs(sin6->sin6_port);
	}
	}
	return -1;
}

const char *net_ss_ntop(struct sockaddr_storage *ss, int show_port)
{
	char s[sizeof(struct sockaddr_storage) + 1];
	static char a[sizeof(struct sockaddr_storage) + 32];
	const char *r;
	switch (ss->ss_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)ss;
		r = inet_ntop(sin->sin_family, &sin->sin_addr, s, sizeof(s));
		if (r == NULL) {
			error(-1, errno, "inet_ntop()");
		}
		if (show_port == 0) {
			snprintf(a, sizeof(a), "%s", s);
		} else {
			int port = htons(sin->sin_port);
			snprintf(a, sizeof(a), "%s:%d", s, port);
		}
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
		r = inet_ntop(sin6->sin6_family, &sin6->sin6_addr, s, sizeof(s));
		if (r == NULL) {
			error(-1, errno, "inet_ntop()");
		}
		if (show_port == 0) {
			snprintf(a, sizeof(a), "%s", s);
		} else {
			int port = htons(sin6->sin6_port);
			snprintf(a, sizeof(a), "[%s]:%d", s, port);
		}
		break;
	}
	case AF_UNIX: {
		struct sockaddr_un *sun = (struct sockaddr_un *)ss;
		memcpy(s, sun->sun_path, sizeof(sun->sun_path));
		s[sizeof(sun->sun_path)] = '\x00';
		if (s[0] == '\x00') {
			s[0] = '@';
		}
		snprintf(a, sizeof(a), "%s", s);
		break;
	}
	default:
		error(-1, 0, "Unknown ss family %d", ss->ss_family);
	}
	return a;
}

int net_parse_sockaddr(struct sockaddr_storage *ss, const char *addr, int default_port)
{
	int force_family = 0;
	char host[256];
	strncpy(host, addr, sizeof(host));
	host[sizeof(host) - 1] = '\x00';

	// Try v6:
	int r = net_gethostbyname(ss, host, default_port, AF_INET6);
	if (r >= 0) {
		return ss->ss_family;
	}

	long port = 0;
	char *colon = strrchr(addr, ':');
	if (colon == NULL || colon[1] == '\0') {
		port = default_port;
		colon = NULL;
	} else {
		char *endptr;
		port = strtol(&colon[1], &endptr, 10);
		if (port < 0 || port > 65535 || *endptr != '\0') {
			port = default_port;
			colon = NULL;
		}
	}

	// Cut at colon
	if (colon) {
		int addr_len = colon - addr >= (int)(sizeof host) ? (int)sizeof(host) - 1
								  : colon - addr;
		host[addr_len] = '\0';
	}
	if (host[0] == '[' && host[strlen(host) - 1] == ']') {
		force_family = AF_INET6;
		host[strlen(host) - 1] = '\x00';
		memmove(host, &host[1], strlen(&host[1]) + 1);
	}

	return net_gethostbyname(ss, host, port, force_family);
}

int net_gethostbyname(struct sockaddr_storage *ss, const char *host, int port,
		      int force_family)
{
	memset(ss, 0, sizeof(struct sockaddr_storage));

	struct in_addr in_addr;
	struct in6_addr in6_addr;

	/* Try ipv4 address first */
	if ((force_family == 0 || force_family == AF_INET) &&
	    inet_pton(AF_INET, host, &in_addr) == 1) {
		struct sockaddr_in *sin4 = (struct sockaddr_in *)ss;
		*sin4 = (struct sockaddr_in){.sin_family = AF_INET,
					     .sin_port = htons(port),
					     .sin_addr = in_addr};
		return AF_INET;
	}

	/* Then ipv6 */
	if ((force_family == 0 || force_family == AF_INET6) &&
	    inet_pton(AF_INET6, host, &in6_addr) == 1) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
		*sin6 = (struct sockaddr_in6){.sin6_family = AF_INET6,
					      .sin6_port = htons(port),
					      .sin6_addr = in6_addr};
		return AF_INET6;
	}

#if 0
	/* Then assume unix socket path */
	if ((force_family == 0 || force_family == AF_UNIX)) {
		struct sockaddr_un *sun = (struct sockaddr_un *)ss;
		sun->sun_family = AF_UNIX;
		strncpy(sun->sun_path, host, UNIX_PATH_MAX);
		// Linux abstract sockets often use @ for zero
		if (sun->sun_path[0] == '@') {
			sun->sun_path[0] = '\x00';
		}
		return AF_UNIX;
	}
#endif

	// error(-1, errno, "inet_pton(\"%s\")", host);
	return -1;
}
