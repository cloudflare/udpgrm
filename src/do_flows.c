// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "list.h"

#include "common.h"

#define TIMESPEC_NSEC(ts) ((ts)->tv_sec * 1000000000ULL + (ts)->tv_nsec)

struct item {
	struct hlist_node in_list;
	struct lru_key key;
	struct lru_value value;
};

#define FLOWS_MAX 256

static void _do_flows(int prog_fd, struct reuseport_storage_key *_key,
		      struct reuseport_storage *s, int verbose, struct hlist_head *flows)
{
	uint32_t flow_entry_timeout_sec = s->dis.flow_entry_timeout_sec;
	if (flow_entry_timeout_sec == 0)
		flow_entry_timeout_sec = FLOW_DEFAULT_TIMEOUT_SEC;

	char *t = key_to_str(_key);
	printf("%s\n", t);
	int sockhash_fd = map_from_prog(prog_fd, "sockhash", NULL);
	if (sockhash_fd < 0)
		error(-1, errno, "map_from_prog()");

	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	uint64_t now = TIMESPEC_NSEC(&ts);

	int gen;
	uint32_t j;
	for (gen = 0; gen < MAX_GENS; gen++) {
		for (j = 0; j < s->max_idx[gen]; j++) {
			uint64_t c = s->cookies[gen][j];
			if (c == 0)
				break;

			uint64_t v = 0;
			int r = bpf_map_lookup_elem(sockhash_fd, &c, &v);
			if (r == -1 || v == 0) {
				// nonexistent socket.
				continue;
			}

			int first = 0;
			struct hlist_node *pos;
			hlist_for_each(pos, &flows[c % FLOWS_MAX])
			{
				struct item *item =
					hlist_entry(pos, struct item, in_list);
				if (item->value.cookie == c) {
					uint64_t age_ns = (now - item->value.last_tx_ns);
					double age_s = age_ns / 1000000000.;
					int stale = age_s > flow_entry_timeout_sec;

					if (stale == 0 || verbose > 0) {
						if (first == 0) {
							printf("\tso_cookie 0x%lx\n", c);
							first = 1;
						}

						printf("\t\t%08x  age %.1fs %s",
						       item->key.rx_hash, age_s,
						       stale ? "(stale)" : "");
						printf("\n");
					}
				}
			}
		}
	}
}

void do_flows(int prog_fd, int map_fd, struct sockaddr_storage *reuseport_ss, int verbose)
{
	/* Indexed by socket cookie */
	struct hlist_head flows[FLOWS_MAX] = {[0 ...(FLOWS_MAX - 1)] = HLIST_HEAD_INIT};

	{
		int lru_fd = map_from_prog(prog_fd, "lru_map", NULL);
		if (lru_fd < 0)
			error(-1, errno, "map_from_prog()");

		struct lru_key key = {};
		int err = bpf_map_get_next_key(lru_fd, NULL, &key);
		while (!err) {
			struct lru_value value = {};
			int r = bpf_map_lookup_elem(lru_fd, &key, &value);
			if (r == 0) {
				/* Impossible to know if it's stale at this point */
				struct item *i =
					(struct item *)calloc(1, sizeof(struct item));
				i->key = key;
				i->value = value;
				hlist_add_head(&i->in_list,
					       &flows[value.cookie % FLOWS_MAX]);
			}
			err = bpf_map_get_next_key(lru_fd, &key, &key);
		}
	}

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
			_do_flows(prog_fd, &key, &s, verbose, flows);
		}

		if (reuseport_ss->ss_family != AF_UNSPEC) {
			// finish loop
			break;
		}

		err = bpf_map_get_next_key(map_fd, &key, &key);
	}
}
