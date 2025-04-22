#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <error.h>
#include <linux/filter.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "common.h"

#include "../ebpf.skel.h"

extern struct ebpf *skel;

void cookies_find_empty(struct reuseport_storage *state, int gen, int sockhash_fd,
			uint64_t cookie, int *prev_pos, int *free_pos, int *gen_len)
{
	*free_pos = -1;
	*prev_pos = -1;
	*gen_len = 0;
	int i, r;
	for (i = 0; i < MAX_SOCKETS_IN_GEN; i++) {
		uint64_t uc = state->cookies[gen % MAX_GENS][i];

		uint64_t v = 0;
		/* Is the cookie pointing to live socket? */
		r = bpf_map_lookup_elem(sockhash_fd, &uc, &v);
		if (!(r != 0 || v == 0)) {
			/* r != 0 means entry unset (not stale, not
			 * good). v == 0 means stale. Socket exists.
			 */
			if (v == cookie && *prev_pos == -1) {
				*prev_pos = i;
			}
			*gen_len = i + 1;
			continue;
		}

		/* Guaranteed empty slot */
		if (*free_pos == -1) {
			*free_pos = i;
			*gen_len = i + 1;
		}
	}
}

void run_cb_update_map(struct msg_value *msg)
{
	int fd = bpf_program__fd(skel->progs.udpgrm_cb_update_map);
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	topts.data_in = msg;
	topts.data_size_in = sizeof(*msg);
	int err = bpf_prog_test_run_opts(fd, &topts);
	if (err != 0 || topts.retval != 0) {
		error(-1, errno, "Failed to call ebpf, err=%d retval=%d\n", err,
		      topts.retval);
	}
}

/* Errors aren't critical. */
void metric_incr_critical(const struct reuseport_storage_key *skey, int counter,
			  int gauge)
{
	{
		struct msg_value msg;
		memset(&msg, 0, sizeof(msg));
		msg = (struct msg_value){
			.skey = *skey,
			.type = GSM_SET_SOCKET_CRITICAL_GAUGE,
			.value = gauge,
		};
		run_cb_update_map(&msg);
	}

	if (counter) {
		struct msg_value msg;
		memset(&msg, 0, sizeof(msg));
		msg = (struct msg_value){
			.skey = *skey,
			.type = GSM_INCR_SOCKET_CRITICAL,
			.value = counter,
		};
		run_cb_update_map(&msg);
	}
}

int map_from_prog(int prog_fd, char *map_name, struct bpf_map_info *user_map_info)
{
	struct bpf_prog_info prog_info = {};
	uint32_t *map_ids = calloc(128, sizeof(uint32_t));
	prog_info.nr_map_ids = 128;
	prog_info.map_ids = (uint64_t)(uintptr_t)map_ids;

	uint32_t prog_info_len = sizeof(prog_info);
	int r = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_info_len);
	if (r != 0) {
		free(map_ids);
		// error(-1, errno, "bpf_prog_get_info_by_fd");
		return -1;
	}

	int i;
	for (i = 0; i < (int)prog_info.nr_map_ids; i += 1) {
		int map_fd = bpf_map_get_fd_by_id(map_ids[i]);
		if (map_fd < 0)
			error(-1, errno, "bpf_map_get_fd_by_id");

		struct bpf_map_info map_info = {};
		uint32_t map_info_len = sizeof(map_info);
		int r = bpf_obj_get_info_by_fd(map_fd, &map_info, &map_info_len);
		if (r < 0) {
			free(map_ids);
			// error(-1, errno, "bpf_map_get_info_by_fd");
			return -1;
		}
		if (strcmp(map_info.name, map_name) == 0) {
			free(map_ids);
			if (user_map_info)
				*user_map_info = map_info;
			return map_fd;
		}
		close(map_fd);
	}

	free(map_ids);
	return -1;
}

void skey_from_ss(struct reuseport_storage_key *skey, struct sockaddr_storage *ss)
{
	*skey = (struct reuseport_storage_key){
		.family = ss->ss_family,
		.src_port = net_get_port(ss),
	};
	switch (ss->ss_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)ss;
		memcpy(&skey->src_ip4, &sin->sin_addr, 4);
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
		memcpy(&skey->src_ip6, &sin6->sin6_addr, 16);
		break;
	}
	}
}

int *map_by_name(char *map_name, uint32_t skip_id)
{
	if (strlen(map_name) > BPF_OBJ_NAME_LEN)
		error(-1, -1, "");

	static int map_fd_list[128];
	uint32_t map_fd_cnt = 0;

	uint32_t next_id = 0;
	while (!bpf_map_get_next_id(next_id, &next_id)) {
		if (skip_id == next_id) {
			continue;
		}

		int fd = bpf_map_get_fd_by_id(next_id);
		if (fd < 0 && errno == ENOENT) {
			continue;
		}
		if (fd < 0) {
			error(-1, errno, "bpf_map_get_fd_by_id(name=%s)", map_name);
		}

		struct bpf_map_info map_info = {};
		uint32_t info_len = sizeof(map_info);
		int r = bpf_obj_get_info_by_fd(fd, &map_info, &info_len);
		if (r != 0) {
			error(-1, errno, "bpf_obj_get_info_by_fd(name=%s)", map_name);
		}

		if (strncmp(map_name, map_info.name, BPF_OBJ_NAME_LEN) != 0) {
			close(fd);
			continue;
		}

		map_fd_list[map_fd_cnt++] = fd;
		if (map_fd_cnt >= ARRAY_SIZE(map_fd_list) - 1) {
			break;
		}
	}
	map_fd_list[map_fd_cnt] = -1;
	return map_fd_list;
}

uint32_t map_fd_to_id(int map_fd)
{
	struct bpf_map_info map_info = {};
	uint32_t info_len = sizeof(map_info);
	int r = bpf_obj_get_info_by_fd(map_fd, &map_info, &info_len);
	if (r != 0) {
		error(-1, errno, "bpf_obj_get_info_by_fd()");
	}

	return map_info.id;
}
