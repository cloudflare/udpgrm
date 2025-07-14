// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
/* Copyright (c) 2025 Cloudflare, Inc.
 * Licensed under either
 * - the Apache 2.0 license found in the LICENSE file, or
 * - the GNU General Public License Version 2 found in the ebpf/LICENSE file
 * at your option. The licenses are also available online at, respectively:
 *     https://opensource.org/license/apache-2-0
 *     https://opensource.org/license/gpl-2-0
 */

/* Public API for udpgrm */

#ifndef UDP_GRM_PUBLIC_H
#define UDP_GRM_PUBLIC_H

#include <linux/filter.h>
#include <stdint.h>

enum udp_grm_socket_opt {
	UDP_GRM_WORKING_GEN = 200,
	UDP_GRM_SOCKET_GEN = 201,
	UDP_GRM_DISSECTOR = 202,
	UDP_GRM_FLOW_ASSURE = 203,
	UDP_GRM_SOCKET_APP = 204
};

enum udp_grm_dissector_type {
	DISSECTOR_FLOW = 0,
	DISSECTOR_CBPF = 1,
	DISSECTOR_BESPOKE = 3,
	DISSECTOR_NOOP = 4,
};

enum udp_grm_dissector_flags {
	DISSECTOR_FLAG_VERBOSE = 0x8000,
};

#define DISSECTOR_FLAGS (DISSECTOR_FLAG_VERBOSE)
#define DISSECTOR_TYPE(x) ((x) & ~DISSECTOR_FLAGS)

#define MAX_INSTR 64
#define LABEL_SZ 100

#define MAX_BESPOKE_SNI 8
#define BESPOKE_SNI_LEN 62

struct udp_grm_dissector {
	uint32_t dissector_type;
	/* Keep LRU flow entry for how long after last tx. */
	uint32_t flow_entry_timeout_sec;

	uint32_t max_apps;
	uint32_t bespoke_digest;

	/* Tubular label */
	char label[LABEL_SZ];
	union {
		struct {
			uint32_t filter_len;
			struct sock_filter filter[MAX_INSTR]; // 8 bytes * 64 == 512 bytes
		};
		struct {
			uint32_t bespoke_hostname_len;
			struct {
				uint8_t app;
				uint8_t _res;
				uint8_t hostname[BESPOKE_SNI_LEN];
			} bespoke_sni[MAX_BESPOKE_SNI]; // 8 strings of 62 bytes
		};
	};
} __attribute__((packed));

struct udp_grm_socket_gen {
	uint32_t socket_gen;
	uint32_t socket_idx;
	uint16_t grm_cookie; // Not to be confused with 64bit socket cookie
	uint16_t _reserved;
};

#endif
