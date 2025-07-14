// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
/* Copyright (c) 2025 Cloudflare, Inc.
 * Licensed under either
 * - the Apache 2.0 license found in the LICENSE file, or
 * - the GNU General Public License Version 2 found in the ebpf/LICENSE file
 * at your option. The licenses are also available online at, respectively:
 *     https://opensource.org/license/apache-2-0
 *     https://opensource.org/license/gpl-2-0
 */

/* When writing ebpf there is always a need to share structures
 * between userspace program and ebpf. This file contains struct
 * definitions used by both. This is not quite ABI, but it's
 * close. There are some changes allowed, like growing the size of the
 * structs, but care should be taken, to ensure the changed userspace
 * will keep on producing reasonable results even if loaded ebpf is
 * older. */

#include "udpgrm.h"

#define _UDP_GRM_MIN 200
#define _UDP_GRM_MAX 204

/* Don't change without rethinking grm_cookie_pack/grm_cookie_unpack */
#define MAX_SOCKETS_IN_GEN 256
#define MAX_GENS 32

/* The  should be keyed also by netns cookie, device index
 * (BINDTODEVICE), and possibly REUSEPORT uid. */
struct reuseport_storage_key {
	/* AF_INET or AF_INET6; type is always SOCK_DGRAM, protocool is always IPPROTO_UDP
	 */
	uint8_t family;
	uint8_t _reserved;
	uint16_t src_port;
	union {
		uint32_t src_ip4;
		uint32_t src_ip6[4];
	};
} __attribute__((__packed__));

#define MAX_APPS 4

struct udp_grm_working_gen {
	uint32_t working_gen;
} __attribute__((packed));

#define FLOW_DEFAULT_TIMEOUT_SEC 125

/* Reuseport group */
struct reuseport_storage {
	uint8_t verbose;

	/* Purely for information. */
	uint64_t netns_cookie;

	/* ID to distinguish reuseport groups one from another */
	uint32_t random_id;

	struct udp_grm_dissector dis;

	uint32_t working_gen[MAX_APPS];
	uint32_t max_idx[MAX_GENS];
	uint64_t cookies[MAX_GENS][MAX_SOCKETS_IN_GEN];

	/* Metrics. Remember about forward compat of this struct in
	 * case userspace is newer version. */
	/* 0. Set from the userspace daemon */
	uint64_t socket_critical_gauge;
	uint64_t socket_critical;

	/* 1. Packet processing */
	uint64_t rx_processed_total;
	uint64_t rx_internal_state_error;
	uint64_t rx_cbpf_prog_error;
	uint64_t rx_packet_too_short_error;

	/* 2. Existing flows */
	uint64_t rx_dissected_ok_total;
	uint64_t rx_flow_ok; /* Flow entry or cookie found, and dispatch went fine. */
	uint64_t rx_flow_rg_conflict; /* Socket chosen from wrong reuseport group */
	uint64_t rx_flow_other_error; /* flow entry or socket cookie pointing to dead
					 socket */
	uint64_t rx_flow_new_unseen;  /* Likely new/fresh flow. */

	uint64_t rx_flow_new_had_expired; /* Subset of rx_flow_new_unseen, hitting expired
					     flow entry, indicative of too short flow
					     entry timeout perhaps. We can't know if the
					     old cookie is legit or not, packet dispatched
					     ot new flows */
	uint64_t rx_flow_new_bad_cookie;  /* Subset of rx_flow_new_unseen,
					   * extracting cookie from packet worked,
					   * but the cookie checksum was invalid. */

	/* 3. New flows */
	uint64_t rx_new_flow_total;
	uint64_t rx_new_flow_working_gen_dispatch_ok;
	uint64_t rx_new_flow_working_gen_dispatch_error;

	/* Sendmsg */
	uint64_t tx_total;
	uint64_t tx_flow_create_ok;
	uint64_t tx_flow_create_from_expired_ok; /* Subset of above. */
	uint64_t tx_flow_create_error;
	uint64_t tx_flow_update_ok;
	uint64_t tx_flow_update_conflict;
};

enum {
	MSG_LOG,
	MSG_REGISTER_SOCKET,
	MSG_SET_WORKING_GEN,
	MSG_SET_DISSECTOR,
	GSM_SET_COOKIES,
	GSM_SET_SOCKET_CRITICAL_GAUGE,
	GSM_INCR_SOCKET_CRITICAL,
};

/* 128 bytes. Size is important, since the ringbuffer is prone to overflow. Use pahole */
struct msg_value {
	int type;
	struct reuseport_storage_key skey;
	union {
		struct {
			uint32_t app_idx;
			uint32_t app_working_gen;
			uint64_t app_so_cookie;
		};
		struct {
			int pid;
			uint64_t socket_cookie;
			uint32_t socket_gen;
			uint32_t socket_app;
		};
		char log[100];
		struct {
			uint32_t sock_gen;
			uint32_t sock_idx;
			uint32_t sock_gen_len;
			uint64_t sock_cookie;
		};
		int value;
	};
};

/* Per socket state. Created on setsockopt. */
struct socket_storage {
	uint32_t sock_gen;
	uint32_t sock_idx;
	uint32_t sock_app;

	// socket cookie is not accesible from setsockopt context,
	// however it is accessible from bind()
	uint64_t so_cookie;

	uint64_t netns_cookie;
};

struct lru_key {
	uint32_t rx_hash;
} __attribute__((__packed__));

struct lru_value {
	uint64_t last_tx_ns;
	uint64_t cookie;
};

/* This is lossy.   */
#define TO_WRK_GEN(_max_apps, app_idx, working_gen)                                      \
	({                                                                               \
		uint32_t max_apps = (_max_apps);                                         \
		if (max_apps == 0)                                                       \
			max_apps = 1;                                                    \
		uint32_t slot_size = MAX_GENS / max_apps;                                \
		((app_idx)*slot_size + ((working_gen) % slot_size));                     \
	})

/* Metrics definitions */
typedef struct {
	char package_version[32];
} metrics_t;

#define GRM_COOKIE_CS(sock_gen, sock_idx)                                                \
	({                                                                               \
		uint8_t cs = (0xD ^ ((sock_idx >> 4) & 0xF) ^ (sock_idx & 0xF) ^         \
			      ((sock_gen >> 4) & 0xF) ^ (sock_gen & 0xF));               \
		cs = (cs & 0x7) ^ ((cs >> 3) & 0x1);                                     \
		cs;                                                                      \
	})

/* Totally assuming MAX_SOCKETS_IN_GEN=256 and MAX_GENS=32 !*/
__attribute__((unused)) static int
grm_cookie_unpack(uint16_t grm_cookie, uint32_t *sock_gen_ptr, uint32_t *sock_idx_ptr)
{
	uint32_t sock_gen = grm_cookie & 0x1f;
	uint32_t sock_idx = (grm_cookie >> 8) & 0xff;
	uint8_t cs_from_cookie = (grm_cookie & 0xff) >> 5;

	uint8_t cs = GRM_COOKIE_CS(sock_gen, sock_idx);
	if (cs_from_cookie != cs) {
		return -1;
	}
	*sock_gen_ptr = sock_gen;
	*sock_idx_ptr = sock_idx;
	return 0;
}

__attribute__((unused)) static void grm_cookie_pack(uint32_t sock_gen, uint32_t sock_idx,
						    uint8_t *v)
{
	sock_gen &= 0x1F;
	sock_idx &= 0xFF;
	uint8_t cs = GRM_COOKIE_CS(sock_gen, sock_idx);

	v[0] = (sock_gen & 0x1F) | (cs << 5);
	v[1] = sock_idx & 0xFF;
	v[2] = 0;
	v[3] = 0;
}
