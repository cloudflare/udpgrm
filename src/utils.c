// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#include <errno.h>
#include <error.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/signalfd.h>

#include "common.h"

const char *optstring_from_long_options(const struct option *opt)
{
	static char optstring[256] = {0};
	char *osp = optstring;

	for (; opt->name != NULL; opt++) {
		if (opt->flag == 0 && opt->val > 0 && opt->val < 256) {
			*osp++ = opt->val;
			switch (opt->has_arg) {
			case optional_argument:
				*osp++ = ':';
				*osp++ = ':';
				break;
			case required_argument:
				*osp++ = ':';
				break;
			}
		}
	}
	*osp++ = '\0';

	if (osp - optstring >= (int)sizeof(optstring)) {
		abort();
	}

	return optstring;
}

int signal_desc(int *sig, int sig_num)
{
	sigset_t mask;
	sigemptyset(&mask);
	int i;
	for (i = 0; i < sig_num; i++) {
		sigaddset(&mask, sig[i]);
	}

	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
		error(-1, errno, "sigprocmask(SIG_BLOCK)");
	}

	int sfd = signalfd(-1, &mask, SFD_NONBLOCK);
	if (sfd == -1) {
		error(-1, errno, "signalfd()");
	}
	return sfd;
}

int fprintf_hex(FILE *out, char *desc, void *addr, int len)
{
	const char hex[] = "0123456789abcdef";
	int i, lines = 0;
	char line[128];
	memset(line, ' ', 128);
	uint8_t *pc = (uint8_t *)addr;

	if (desc != NULL) {
		fprintf(out, "%s:\n", desc);
	}

	for (i = 0; i < len; i++) {
		if ((i % 16) == 0) {
			if (i != 0) {
				fprintf(out, "%.*s\n", 128, line);
				lines++;
			}
			snprintf(line, 128, "  0x%04x: ", i);
		}

		line[10 + (i % 16) * 3 + 0] = hex[(pc[i] >> 4) & 0xf];
		line[10 + (i % 16) * 3 + 1] = hex[pc[i] & 0xf];

		if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
			line[59 + (i % 16)] = '.';
		} else {
			line[59 + (i % 16)] = pc[i];
		}
	}

	while ((i % 16) != 0) {
		line[10 + (i % 16) * 3 + 0] = ' ';
		line[10 + (i % 16) * 3 + 1] = ' ';
		line[59 + (i % 16)] = ' ';
		i++;
	}

	fprintf(out, "%.*s\n", 128, line);
	lines++;
	return lines;
}

size_t snprintfcat(char *buf, size_t size, char const *fmt, ...)
{
	size_t result;
	va_list args;
	size_t len = strnlen(buf, size);

	va_start(args, fmt);
	result = vsnprintf(buf + len, size - len, fmt, args);
	va_end(args);

	return result + len;
}

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}
