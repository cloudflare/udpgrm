// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <error.h>
#include <stdio.h>

#include "common.h"

static int gen_pointed_by_wrk_gen(uint32_t gen, struct reuseport_storage *s)
{
	int app_idx;
	for (app_idx = 0; app_idx < MAX_APPS; app_idx++) {
		if (gen == TO_WRK_GEN(s->dis.max_apps, app_idx, s->working_gen[app_idx]))
			return app_idx;
	}
	return -1;
}

/* Makes dst zero-terminated if it's not */
static void safe_strcat(char *restrict dst, char *restrict src, size_t dst_sz)
{
	size_t l = strnlen(dst, dst_sz);
	if (l < dst_sz) {
		size_t b = dst_sz - l; // must be >= 0
		size_t c = strlen(src);
		size_t ll = c < b ? c : b;
		memmove(&dst[l], src, ll);
		l += ll;
	}
	if (l == dst_sz) {
		l = dst_sz - 1;
	}
	dst[l] = '\x00';
}

char *key_to_str(struct reuseport_storage_key *key)
{
	char a[16];
	char b[48];
	inet_ntop(AF_INET, &key->src_ip4, a, sizeof(a));
	inet_ntop(AF_INET6, &key->src_ip6, b, sizeof(b));
	static char t[64];
	if (key->family == AF_INET) {
		snprintf(t, sizeof(t), "%s:%d", a, key->src_port);

	} else if (key->family == AF_INET6) {
		snprintf(t, sizeof(t), "[%s]:%d", b, key->src_port);
	} else {
		snprintf(t, sizeof(t), "fam=%d type=dgram proto=udp %s/[%s]:%d",
			 key->family, a, b, key->src_port);
	}
	return t;
}

static void _do_list(struct reuseport_storage_key *key, struct reuseport_storage *s,
		     int verbose, int sockhash_fd, char *msg_note)
{
	char *t = key_to_str(key);

	char a[32];
	uint32_t dissector_type = s->dis.dissector_type & ~DISSECTOR_FLAGS;
	switch (dissector_type) {
	case DISSECTOR_FLOW:
		snprintf(a, sizeof(a), "flow");
		break;
	case DISSECTOR_CBPF:
		snprintf(a, sizeof(a), "cbpf");
		break;
	case DISSECTOR_BESPOKE:
		snprintf(a, sizeof(a), "bespoke");
		break;
	case DISSECTOR_NOOP:
		snprintf(a, sizeof(a), "noop");
		break;
	default:
		snprintf(a, sizeof(a), "%d", dissector_type);
		break;
	}

	printf("%s%s%s\n\tnetns 0x%lx  dissector %s", t, msg_note != NULL ? " " : "",
	       msg_note == NULL ? "" : msg_note, s->netns_cookie, a);
	if (dissector_type == DISSECTOR_FLOW) {
		printf("  flow_timeout_sec %u", s->dis.flow_entry_timeout_sec);
	} else if (dissector_type == DISSECTOR_CBPF) {
		printf("  apps %d  filter_len %d", s->dis.max_apps, s->dis.filter_len);
	} else if (dissector_type == DISSECTOR_BESPOKE) {
		printf("  digest 0x%x", s->dis.bespoke_digest);
	} else {
		// No action needed
	}

	if (s->dis.label[0] != '\x00') {
		printf("  label %.*s", LABEL_SZ, s->dis.label);
	}

	if (s->verbose) {
		printf("  verbose");
	}

	printf("\n");

	if (sockhash_fd >= 0) {
		printf("\tsocket generations:\n");
		uint32_t i, j;
		char line[4096]; // need at least 3230 bytes
		for (i = 0; i < MAX_GENS; i++) {
			int this_app = gen_pointed_by_wrk_gen(i, s);
			line[0] = '\x00';
			for (j = 0; j < s->max_idx[i]; j++) {
				uint64_t c = s->cookies[i][j];
				if (c == 0)
					break;

				uint64_t v = 0;
				int r = bpf_map_lookup_elem(sockhash_fd, &c, &v);
				if (verbose) {
					snprintf(a, sizeof(a), "%d:", j);
					safe_strcat(line, a, sizeof(line));
				}

				if (r == -1 || v == 0) {
					// nonexistent socket.
					if (this_app == -1 && verbose == 0) {
						// Ignore in print unless
						// working_gen
						continue;
					}
					snprintf(a, sizeof(a), "dead ");
				} else {
					snprintf(a, sizeof(a), "0x%lx ", c);
				}
				safe_strcat(line, a, sizeof(line));
			}
			if (strlen(line) > 0 || this_app != -1) {
				printf("\t\tgen %2d  %s", i, line);
				if (this_app != -1) {
					printf(" <= ");

					int a;
					for (a = 0; a < MAX_APPS; a++) {
						if (i == TO_WRK_GEN(s->dis.max_apps, a,
								    s->working_gen[a]))
							printf(" app %d  gen %d", a,
							       s->working_gen[a]);
					}
				}
				printf("\n");
			}
		}
	}
	int metrics_cnt = 0;

#define METRIC(token)                                                                    \
	if (s->token > 0 || verbose) {                                                   \
		if (metrics_cnt++ == 0)                                                  \
			printf("\tmetrics:\n");                                          \
		printf("\t\t" #token " %lu\n", s->token);                                \
	}

	METRIC(socket_critical_gauge);
	METRIC(socket_critical);

	METRIC(rx_processed_total);
	METRIC(rx_internal_state_error);
	METRIC(rx_cbpf_prog_error);
	METRIC(rx_packet_too_short_error);

	METRIC(rx_dissected_ok_total);
	METRIC(rx_flow_ok);
	METRIC(rx_flow_rg_conflict);
	METRIC(rx_flow_other_error);
	METRIC(rx_flow_new_unseen);
	METRIC(rx_flow_new_had_expired);
	METRIC(rx_flow_new_bad_cookie);

	METRIC(rx_new_flow_total);
	METRIC(rx_new_flow_working_gen_dispatch_ok);
	METRIC(rx_new_flow_working_gen_dispatch_error);

	METRIC(tx_total);
	METRIC(tx_flow_create_ok);
	METRIC(tx_flow_create_from_expired_ok);
	METRIC(tx_flow_create_error);
	METRIC(tx_flow_update_ok);
	METRIC(tx_flow_update_conflict);
}

void do_list(int prog_fd, int map_fd, struct sockaddr_storage *reuseport_ss, int verbose)
{
	int sockhash_fd = map_from_prog(prog_fd, "sockhash", NULL);
	/* allow it to be not found/-1 */

	struct reuseport_storage_key key = {};
	int err = 0;

	if (reuseport_ss->ss_family != AF_UNSPEC) {
		skey_from_ss(&key, reuseport_ss);
	} else {
		bpf_map_get_next_key(map_fd, NULL, &key);
	}
	while (!err) {
		struct reuseport_storage s = {};
		int r = bpf_map_lookup_elem(map_fd, &key, &s);
		if (r == 0) {
			_do_list(&key, &s, verbose, sockhash_fd, NULL);
		}

		if (reuseport_ss->ss_family != AF_UNSPEC) {
			// finish loop
			break;
		}

		err = bpf_map_get_next_key(map_fd, &key, &key);
	}

	struct bpf_map_info good_map_info = {};
	uint32_t info_len = sizeof(good_map_info);
	int r = bpf_obj_get_info_by_fd(map_fd, &good_map_info, &info_len);
	if (r != 0) {
		error(-1, errno, "bpf_obj_get_info_by_fd()");
	}

	int *map_fd_list = map_by_name("reuseport_stora", map_fd_to_id(map_fd));
	int map_fd_cnt = 0;
	for (map_fd_cnt = 0; map_fd_list && map_fd_list[map_fd_cnt] >= 0; map_fd_cnt++) {
		int map_fd = map_fd_list[map_fd_cnt];

		struct bpf_map_info map_info = {};
		uint32_t info_len = sizeof(map_info);
		int r = bpf_obj_get_info_by_fd(map_fd, &map_info, &info_len);
		if (r != 0) {
			error(-1, errno, "bpf_obj_get_info_by_fd()");
		}

		if (good_map_info.key_size != map_info.key_size) {
			fprintf(stderr, "[!] map %u seems off, skipping\n", map_info.id);
		}

		struct reuseport_storage_key key = {};
		if (reuseport_ss->ss_family != AF_UNSPEC) {
			skey_from_ss(&key, reuseport_ss);
		} else {
			bpf_map_get_next_key(map_fd, NULL, &key);
		}
		err = 0;
		while (!err) {
			struct reuseport_storage s = {};
			int r = bpf_map_lookup_elem(map_fd, &key, &s);
			if (r == 0) {
				_do_list(&key, &s, verbose, -1, "(old)");
			}

			if (reuseport_ss->ss_family != AF_UNSPEC) {
				// finish loop
				break;
			}

			err = bpf_map_get_next_key(map_fd, &key, &key);
		}
	}
}
