// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "list.h"

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define TIMESPEC_NSEC(ts) ((ts)->tv_sec * 1000000000ULL + (ts)->tv_nsec)

uint64_t realtime_now()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return TIMESPEC_NSEC(&ts);
}
/* Ctrl buffer must have CMSG_SPACE(256*sizeof(int)) space at least. */
static void set_scm_rights_cmsg(struct msghdr *msgh, int single_ctrl_sz, int fds[],
				int fds_num)
{
	int space = 0;
	/* To ensure CMSG_NXTHDR contorllen must be
	 * large and the buffer must be zeroed. */
	msgh->msg_controllen = single_ctrl_sz;
	memset(msgh->msg_control, 0, msgh->msg_controllen);

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(msgh);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int) * fds_num);
	memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * fds_num);
	space += CMSG_SPACE(sizeof(int) * fds_num);

	// cmsg = CMSG_NXTHDR(msgh, cmsg);
	// space += CMSG_SPACE(sizeof(val));

	msgh->msg_controllen = space;
}

/* This is synchronous */
static int tubular_register(char *tubular_path, char *label, int fds[], int fds_num)
{
	int s = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (s < 0) {
		return errno;
	}

	struct timeval timeout = {.tv_sec = 1};

	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

	struct sockaddr_un sun = {};
	sun.sun_family = AF_UNIX;
	memcpy(sun.sun_path, tubular_path,
	       MIN(strlen(tubular_path), sizeof(sun.sun_path)));
	int r = connect(s, (struct sockaddr *)&sun,
			net_ss_size((struct sockaddr_storage *)&sun));
	if (r != 0) {
		close(s);
		return errno;
	}

	// sendmsg();
	char payload[256];
	snprintf(payload, sizeof(payload), "%s#", label);

	struct iovec iovec = {
		.iov_base = payload,
		.iov_len = strlen(payload),
	};

	int ctrl_sz = CMSG_SPACE(sizeof(int) * fds_num) + 1024;
	char ctrl[ctrl_sz];

	struct msghdr msg = {
		.msg_iov = &iovec,
		.msg_iovlen = 1,
		.msg_control = ctrl,
		.msg_controllen = ctrl_sz,
	};

	set_scm_rights_cmsg(&msg, ctrl_sz, fds, fds_num);
	r = sendmsg(s, &msg, 0);
	if (r != (int)strlen(payload)) {
		close(s);
		return errno;
	}

	char buf[1024] = {};
	int n = read(s, buf, sizeof(buf));
	if (n < 0) {
		close(s);
		return errno;
	}

	close(s);
	if (n != 2 || strcmp(buf, "OK") != 0) {
		return EPROTO;
	}
	return 0;
}

LIST_HEAD(list_of_tubular_sockets);

struct reuseport_group {
	struct list_head in_list;
	uint32_t random_id;
	uint64_t last_modified;
	int max_idx[MAX_GENS];
	int sockets[MAX_GENS][MAX_SOCKETS_IN_GEN];
};

int reuseport_groups_empty() { return list_empty(&list_of_tubular_sockets); }

struct reuseport_group *reuseport_group_lookup(struct reuseport_storage *state)
{
	struct list_head *pos;
	list_for_each(pos, &list_of_tubular_sockets)
	{
		struct reuseport_group *sk_group =
			hlist_entry(pos, struct reuseport_group, in_list);
		if (sk_group->random_id == state->random_id) {
			return sk_group;
		}
	}
	return NULL;
}

struct reuseport_group *reuseport_group_lookup_or_add(struct reuseport_storage *state)
{
	struct reuseport_group *sk_group = reuseport_group_lookup(state);
	if (sk_group)
		return sk_group;

	sk_group = calloc(1, sizeof(struct reuseport_group));
	sk_group->random_id = state->random_id;
	sk_group->last_modified = realtime_now();
	list_add(&sk_group->in_list, &list_of_tubular_sockets);
	return sk_group;
}

int reuseport_group_maybe_delete(struct reuseport_group *sk_group)
{
	int g;
	for (g = 0; g < MAX_GENS; g++) {
		if (sk_group->max_idx[g] != 0) {
			return 0;
		}
	}
	list_del(&sk_group->in_list);
	free(sk_group);
	return 1;
}

void tubular_close_wg(struct reuseport_group *sk_group, int wg);

void reuseport_groups_maybe_cleanup_stale()
{
	uint64_t now = realtime_now();
	struct list_head *pos, *tmp;
	list_for_each_safe(pos, tmp, &list_of_tubular_sockets)
	{
		struct reuseport_group *sk_group =
			hlist_entry(pos, struct reuseport_group, in_list);
		// 10 seconds
		if (now - sk_group->last_modified > 10 * 1000000000ULL) {
			printf("[#] cleaning up stale tubular sockets\n");
			int g;
			for (g = 0; g < MAX_GENS; g++) {
				tubular_close_wg(sk_group, g);
			}
			reuseport_group_maybe_delete(sk_group);
		}
	}
}

/* Should caller close the top fd or did we steal it? */
int tubular_maybe_preserve_fd(struct reuseport_storage *state, int gen, int gen_len,
			      int free_pos, int f)
{
	if (state->dis.label[0] != '\x00') {
		struct reuseport_group *sk_group = reuseport_group_lookup_or_add(state);
		sk_group->max_idx[gen % MAX_GENS] = gen_len;
		int *fd_ptr = &sk_group->sockets[gen % MAX_GENS][free_pos];
		if (*fd_ptr > 0)
			close(*fd_ptr);
		*fd_ptr = f;
		sk_group->last_modified = realtime_now();
		return 0;
	}
	return 1;
}

void tubular_close_wg(struct reuseport_group *sk_group, int wg)
{
	int i;
	int max_idx = sk_group->max_idx[wg % MAX_GENS];
	for (i = 0; i < max_idx; i++) {
		int *fd_ptr = &sk_group->sockets[wg % MAX_GENS][i];
		if (*fd_ptr > 0)
			close(*fd_ptr);
		*fd_ptr = -1;
	}
	sk_group->max_idx[wg % MAX_GENS] = 0;
}

/* returns errno  */
int tubular_maybe_register(struct reuseport_storage *state, int wg, char *tubular_path)
{
	int err = 0;
	if (state->dis.label[0] != '\x00') {
		struct reuseport_group *sk_group = reuseport_group_lookup(state);

		if (tubular_path == NULL) {
			err = ENOENT;
		} else if (sk_group == NULL) {
			// No fds, we could send empty message to tubular
			printf("No new sockets to register to tubular wg=%d\n", wg);
			err = EBADF;
		} else {
			int max_idx = sk_group->max_idx[wg];
			char label[LABEL_SZ + 1];
			memcpy(label, state->dis.label, LABEL_SZ);
			label[LABEL_SZ] = '\x00';
			err = tubular_register(tubular_path, label, sk_group->sockets[wg],
					       max_idx);
		}

		if (sk_group) {
			tubular_close_wg(sk_group, wg);
			reuseport_group_maybe_delete(sk_group);
		}
	}
	return err;
}
