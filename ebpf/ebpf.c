#include <linux/bpf.h>
#include <linux/types.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <linux/filter.h>

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/swab.h>

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include <errno.h>

#include "../include/udpgrm_internal.h"
#include "siphash.h"

#include "ebpf_internal.h"

#include "ebpf_inter.c"

#include "ebpf_bespoke.c"

char _license[] SEC("license") = "GPL";

static void *empty_percpu_page()
{
	int key = 0;
	void *value = bpf_map_lookup_elem(&percpu_array_map, &key);
	if (value != NULL) {
		memset(value, 0, PERCPU_ARRAY_SIZE);
	}
	return value;
}

static void _skey_from_bpf_sock(struct reuseport_storage_key *skey, struct bpf_sock *sk)
{
	*skey = (struct reuseport_storage_key){
		.family = sk->family,
		.src_port = sk->src_port,
	};
	if (sk->family == AF_INET) {
		skey->src_ip4 = sk->src_ip4;
	} else if (sk->family == AF_INET6) {
		skey->src_ip6[0] = sk->src_ip6[0];
		skey->src_ip6[1] = sk->src_ip6[1];
		skey->src_ip6[2] = sk->src_ip6[2];
		skey->src_ip6[3] = sk->src_ip6[3];
	}
}

/* Too large for stack. Put it in RO. */
static struct reuseport_storage empty_state = {};

static struct reuseport_storage *get_state(struct bpf_sock *sk, int create,
					   int *created_ptr)
{
	struct reuseport_storage_key skey;
	_skey_from_bpf_sock(&skey, sk);
	struct reuseport_storage *state =
		bpf_map_lookup_elem(&reuseport_storage_map, &skey);
	if (state == NULL && create) {
		int r = bpf_map_update_elem(&reuseport_storage_map, &skey, &empty_state,
					    BPF_NOEXIST);
		if (r != 0) {
			/* Must be present, otherwise optimized out. */
			log_printf("new state error %d\n", r);
		}
		if (created_ptr)
			*created_ptr = 1;
		log_printfs(&skey, "[#] socket group created\n");
		state = bpf_map_lookup_elem(&reuseport_storage_map, &skey);
	}
	return state;
}

static uint32_t count_ip_flow_hash(struct ip_flow_hash *data)
{
	/* Hardcode key to allow compiler to inline it. */
	static const char siphash_key[16] = {0xd9, 0xbd, 0xd7, 0xf6, 0xa0, 0xb3,
					     0x49, 0x83, 0x10, 0xb7, 0x49, 0x0f,
					     0x75, 0x56, 0xfd, 0x4c};
	return hsiphash(data, sizeof(struct ip_flow_hash), siphash_key);
}

__attribute__((noinline)) int dissector_flow(struct sk_reuseport_md *md,
					     uint32_t *hash_ptr,
					     uint32_t reuseport_group_id)
{
	struct ip_flow_hash data = {};
	data.reuseport_group_id = reuseport_group_id;
	int r = 0;
	switch (md->eth_protocol) {
	case bpf_htons(ETH_P_IP):
		r = bpf_skb_load_bytes_relative(md, offsetof(struct iphdr, saddr),
						&data.remote_ip, 4, BPF_HDR_START_NET);
		break;

	case bpf_htons(ETH_P_IPV6):
		r = bpf_skb_load_bytes_relative(md, offsetof(struct ipv6hdr, saddr),
						&data.remote_ip, 16, BPF_HDR_START_NET);
		break;

	default:
		// Is it even possible to see here stuff like vlans?
		return 1;
	}
	r |= bpf_skb_load_bytes(md, offsetof(struct udphdr, source), &data.remote_port,
				2);
	if (r != 0)
		return r;

	if (hash_ptr != NULL)
		*hash_ptr = count_ip_flow_hash(&data);
	return 0;
}

__attribute__((noinline)) int dissector_cbpf(struct sk_reuseport_md *md,
					     struct reuseport_storage *state,
					     uint16_t *grm_cookie_ptr,
					     uint32_t *app_idx_ptr)
{
	if (state == NULL || app_idx_ptr == NULL || grm_cookie_ptr == NULL) {
		// Never reached
		return -1;
	}

	int r = 0;
	int retval = 0;
	if (state->dis.bespoke_digest == 0) {
		r = interpret_cbpf(md, state, &retval);
	} else {
		r = run_bespoke_by_digest(md, state->dis.bespoke_digest, state, &retval);
	}

	if (r != IERR_OK) {
		// log_printf("BC return error %d  retval 0x%x\n", r, retval);
		return r;
	}

	{
		uint32_t app_idx = (uint32_t)retval - 0x80000000ULL;
		if (app_idx >= 0 && app_idx < state->dis.max_apps) {
			*app_idx_ptr = app_idx;
			/* the same as per ret=-1 means "new flow" */
			return IERR_BADRETURNVALUE;
		} else if ((retval < 0 || retval > 0xffff)) {
			return IERR_BADRETURNVALUE;
		} else {
			// valid cookie
		}
	}
	// log_printf("BC return ok retval 0x%x\n", retval);
	*grm_cookie_ptr = retval;
	return 0;
}

static int flow_assure(struct reuseport_storage *state, struct socket_storage *s,
		       uint32_t hash);

SEC("sk_reuseport")
int udpgrm_reuseport_prog(struct sk_reuseport_md *md)
{
	// [*] First stage, parsing
	struct reuseport_storage *state = get_state(md->sk, 0, NULL);
	if (state == NULL) {
		/* Funnily enough we can't even log error here */
		return 1;
	}
	METRIC_INC(rx_processed_total);

	/* No way to retrieve netns cookie. */
	uint64_t sock_cookie = -1;
	uint32_t sock_gen = -1, sock_idx = -1;
	uint8_t dcid_len = 0;
	uint32_t hash = -1;
	uint32_t app_idx = 0;
	int r = 0;

	uint32_t dis = DISSECTOR_TYPE(state->dis.dissector_type);
	switch (dis) {
	case DISSECTOR_FLOW: {
		r = dissector_flow(md, &hash, state->random_id);
		if (r != 0)
			goto skb_load_bytes_error;
		goto have_hash;
		break;
	}
	case DISSECTOR_CBPF:
	case DISSECTOR_BESPOKE: {
		uint16_t grm_cookie = 0;
		r = dissector_cbpf(md, state, &grm_cookie, &app_idx);
		if (r == IERR_LOAD) {
			goto skb_load_bytes_error;
		} else if (r == IERR_BADRETURNVALUE) {
			// New flow, not short packet, and not long with correct length
			sock_cookie = -1ULL;
		} else if (r == IERR_OK) {
			r = grm_cookie_unpack(grm_cookie, &sock_gen, &sock_idx);
			if (r == 0) {
				sock_cookie =
					state->cookies[sock_gen % MAX_GENS]
						      [sock_idx % MAX_SOCKETS_IN_GEN];
			} else {
				if (state->verbose)
					log_printf(
						"[#] cookie checksum fail. Cookie extracted by cBPF 0x%04x\n",
						grm_cookie);
				sock_cookie = -2ULL;
			}
			// cookie == 0 if hitting empty slot, think:
			// attacker spraying
		} else {
			goto cbpf_prog_error;
		}
		goto have_cookie;
		break;
	}
	case DISSECTOR_NOOP: {
		goto have_third_stage;
		break;
	}
	default:
		METRIC_INC(rx_internal_state_error);
		return SK_PASS;
	}

	if (0) {
	skb_load_bytes_error:;
		METRIC_INC(rx_packet_too_short_error);
		return SK_PASS;
	cbpf_prog_error:;
		METRIC_INC(rx_cbpf_prog_error);
		return SK_PASS;
	}

	// [*] Second stage, existing flow dispatch
	if (0) {
	have_hash:;
		METRIC_INC(rx_dissected_ok_total);

		struct lru_key key = {.rx_hash = hash};
		struct lru_value *value = bpf_map_lookup_elem(&lru_map, &key);

		uint64_t now = bpf_ktime_get_ns();

		uint32_t flow_entry_timeout_sec = state->dis.flow_entry_timeout_sec;
		if (flow_entry_timeout_sec == 0)
			flow_entry_timeout_sec = FLOW_DEFAULT_TIMEOUT_SEC;

		if (value != NULL &&
		    (now - value->last_tx_ns) <= SEC_TO_NSEC(flow_entry_timeout_sec)) {
			if (state->verbose)
				log_printf(
					"[#] by hash ok=#%x existing flow, sock "
					"so_cookie=0x%x\n",
					hash, value->cookie);
			int err =
				bpf_sk_select_reuseport(md, &sockhash, &value->cookie, 0);
			if (err == 0) {
				METRIC_INC(rx_flow_ok);
				if (state->verbose)
					log_printf("[#] existing flow ok\n");
				return SK_PASS;
			}
			if (err == -EBADF) {
				// rx flow entry conflict across reuseport groups
				METRIC_INC(rx_flow_rg_conflict);
			} else {
				METRIC_INC(rx_flow_other_error);
			}
		} else {
			METRIC_INC(rx_flow_new_unseen);
			if (value != NULL) {
				/* This metric double-counts, it's a
				 * subset of
				 * rx_flow_new_unseen. Remember we
				 * don't create flow entries in RX
				 * path. */
				METRIC_INC(rx_flow_new_had_expired);
			}
		}

		if (state->verbose)
			log_printf("[-] by hash fail=#%x\n", hash);
	}

	if (0) {
	have_cookie:;
		METRIC_INC(rx_dissected_ok_total);

		int err = bpf_sk_select_reuseport(md, &sockhash, &sock_cookie, 0);
		if (err == 0) {
			METRIC_INC(rx_flow_ok);
			if (dcid_len == 0) {
				if (state->verbose)
					log_printf(
						"[#] by cookie ok so_cookie=0x%lx "
						"gen=0x%x "
						"idx=0x%x (short)\n",
						sock_cookie, sock_gen, sock_idx);
			} else {
				if (state->verbose)
					log_printf(
						"[#] by cookie ok so_cookie=0x%lx "
						"gen=0x%x "
						"idx=0x%x (long) dcid_len=%d\n",
						sock_cookie, sock_gen, sock_idx,
						dcid_len);
			}
			return SK_PASS;
		} else {
			if (err == -EBADF) {
				// rx flow entry conflict across reuseport groups
				METRIC_INC(rx_flow_rg_conflict);
			} else if (sock_cookie == -1ULL || sock_cookie == 0ULL ||
				   sock_cookie == -2ULL) {
				// DCID bad length or cookie lookup hit empty slot.
				METRIC_INC(rx_flow_new_unseen);
				if (sock_cookie == -2ULL) {
					METRIC_INC(rx_flow_new_bad_cookie);
				}
			} else {
				// Socket cookie not obvioiusly
				// wrong. DCID length is
				// fine. Shouldn't happen.
				METRIC_INC(rx_flow_other_error);
			}
			if (state->verbose)
				log_printf(
					"[-] by cookie fail so_cookie=0x%lx gen=0x%x "
					"idx=0x%x dcid_len=%d\n",
					sock_cookie, sock_gen, sock_idx, dcid_len);
		}
	}

	if (0) {
	have_third_stage:;
		METRIC_INC(rx_dissected_ok_total);
		METRIC_INC(rx_flow_new_unseen);
	}

	// [*] Third stage, new flow dispatch
	METRIC_INC(rx_new_flow_total);
	{
		// select socket from working generation.
		// use app_idx potentially decoded from cBPF
		uint32_t wrk_gen = TO_WRK_GEN(state->dis.max_apps, app_idx,
					      state->working_gen[app_idx % MAX_APPS]);
		uint32_t max_idx = state->max_idx[wrk_gen % MAX_GENS];

		sock_cookie = state->cookies[wrk_gen % MAX_GENS]
					    [(md->hash % max_idx) % MAX_SOCKETS_IN_GEN];

		int err = bpf_sk_select_reuseport(md, &sockhash, &sock_cookie, 0);
		if (err == 0) {
			METRIC_INC(rx_new_flow_working_gen_dispatch_ok);
			if (state->verbose)
				log_printf(
					"[o] ok from working_gen=%d, max=%d, mdhash=0x%x "
					"so_cookie=0x%lx\n",
					wrk_gen, max_idx, md->hash, sock_cookie);
			return SK_PASS;
		} else {
			METRIC_INC(rx_new_flow_working_gen_dispatch_error);

			if (state->verbose)
				log_printf("[#] mdhash=#%x fallback to no selection!\n",
					   md->hash);
			return SK_PASS;
		}
	}
}

struct task_struct {
	int pid;
} __attribute__((preserve_access_index));

int dissector_cmp(struct udp_grm_dissector *a, struct udp_grm_dissector *b)
{
	if ((a->dissector_type & ~DISSECTOR_FLAGS) !=
	    (b->dissector_type & ~DISSECTOR_FLAGS)) {
		return -1;
	}
	uint8_t *_a = (uint8_t *)a;
	uint8_t *_b = (uint8_t *)b;
	return memcmp(_a + 4, _b + 4, sizeof(struct udp_grm_dissector) - 4);
}

union setsockopt_opts {
	struct udp_grm_dissector dis;
	struct udp_grm_working_gen wrk;
	struct udp_grm_socket_gen sk;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	uint32_t value;
};

SEC("cgroup/setsockopt")
int udpgrm_setsockopt(struct bpf_sockopt *ctx)
{

	if (!(ctx->level == IPPROTO_UDP && ctx->optname >= _UDP_GRM_MIN &&
	      ctx->optname <= _UDP_GRM_MAX)) {
		/* Pass-thru */
		if (ctx->optlen > 4096)
			ctx->optlen = 0;
		return 1;
	}

	/* What if we have more than one bpf setsockopt hook running?
	 * To figure it out check two things. First, if optlen==-1,
	 * then definitely there was a bpf already in place. optlen=-1
	 * means: skip the kernel setsocktopt() and go direct back to
	 * userspace after the ebpf hooks. Secondly, retval is
	 * initially zero. If it isn't zero it means someone had set
	 * it and we should not process the query anymore. */
	if (ctx->optlen == -1 || bpf_get_retval() != 0) {
		return 1;
	}

	/* Workarond for: error: Looks like the BPF stack limit of 512
	 * bytes is exceeded. Please move large on stack variables
	 * into BPF per-cpu array map. */
	/* Sanity check that we didn't overshoot the percpu_page */
	union setsockopt_opts *data = empty_percpu_page();
	if (data == NULL || sizeof(union setsockopt_opts) > PERCPU_ARRAY_SIZE) {
		bpf_set_retval(-ENOBUFS);
		return 0;
	}

	/* Careful memcpy dance to avoid upsetting the fragile verfier. */
	uint8_t *optval_end = (uint8_t *)ctx->optval_end;
	uint8_t *optval = (uint8_t *)ctx->optval;

	if (optval + sizeof(union setsockopt_opts) <= optval_end) {
		memcpy(data, optval, sizeof(union setsockopt_opts));
	} else if (optval + 116 + 4 + 256 <= optval_end) {
		memcpy(data, optval, 116 + 4 + 256);
	} else if (optval + 116 <= optval_end) {
		memcpy(data, optval, 116);
	} else if (optval + sizeof(struct sockaddr_in6) <= optval_end) {
		memcpy(data, optval, sizeof(struct sockaddr_in6));
	} else if (optval + 16 <= optval_end) {
		/* This is also sizeof(struct sockaddr_in) */
		memcpy(data, optval, 16);
	} else if (optval + 12 <= optval_end) {
		memcpy(data, optval, 12);
	} else if (optval + 8 <= optval_end) {
		memcpy(data, optval, 8);
	} else if (optval + 4 <= optval_end) {
		memcpy(data, optval, 4);
	} else {
		bpf_set_retval(-EFAULT);
		return 0;
	}

	/* While we don't strictly need socket storage, it's a good
	 * check for whether the socket had been bound() yet. Fail if
	 * the socket hasn't been bound. */
	struct socket_storage *s = bpf_sk_storage_get(&sk_storage_map, ctx->sk, 0, 0);
	if (s == NULL) {
		bpf_set_retval(-EBADF);
		return 0;
	}

	/* We create reuseport storage on first setsockopt. We
	 * strictly don't need that in UDP_GRM_SOCKET_GEN, but we
	 * do need reuseport storage in daemon later, right? */
	int created = 0;
	struct reuseport_storage *state = get_state(ctx->sk, 1, &created);
	if (state == NULL) {
		bpf_set_retval(-EBADF);
		return 0;
	}
	if (created != 0) {
		/* Preserve first socket netns. */
		state->random_id = bpf_get_prandom_u32();
		state->netns_cookie = s->netns_cookie;

		/* This might happen in case of implicit creation */
		state->verbose = 0;
		state->dis.dissector_type = DISSECTOR_FLOW; // 0
	}

	if (state->netns_cookie != s->netns_cookie) {
		/* Sanity check. Reuseport group network namespace on
		 * creation must be equal to socket network namespace
		 * on creation. */
		bpf_set_retval(-EBADF);
		return 0;
	}

	if (ctx->optname == UDP_GRM_WORKING_GEN) {
		int app_idx = s->sock_app % MAX_APPS;
		{
			int old = state->working_gen[app_idx];
			state->working_gen[app_idx] = data->wrk.working_gen;

			static struct msg_value e;
			e.type = MSG_SET_WORKING_GEN;
			e.app_idx = app_idx;
			e.app_working_gen = data->wrk.working_gen;
			_skey_from_bpf_sock(&e.skey, ctx->sk);

			log_printfs(&e.skey, "[+] setting working gen %d (old=%d) (app=%d)\n", data->wrk.working_gen, old,
				   app_idx);

			unsigned ll = offsetof(struct msg_value, app_so_cookie) + 8;
			int r = bpf_ringbuf_output(&msg_rb, &e, ll, 0);
			if (r != 0) {
				log_printf("[!] Error: rb failed: EGAIN\n");
				// We don't incr critical metric as we return EGAIN
				bpf_set_retval(-EAGAIN);
				return 0;
			}
		}

		ctx->optlen = -1;
		bpf_set_retval(0);
		return 1;
	}

	if (ctx->optname == UDP_GRM_SOCKET_GEN) {
		if (s->sock_gen != data->sk.socket_gen || s->sock_idx == 0xffffffff) {
			// Socket gen is set to a new value or the socket is not yet
			// registered. Post a message to udpgrm daemon to register with
			// requested socket generation.
			struct task_struct *ts = bpf_get_current_task_btf();

			s->sock_gen = data->sk.socket_gen;

			static struct msg_value e;
			e.type = MSG_REGISTER_SOCKET;
			e.pid = ts->pid;
			e.socket_cookie = s->so_cookie;
			e.socket_gen = data->sk.socket_gen;
			e.socket_app = s->sock_app;
			_skey_from_bpf_sock(&e.skey, ctx->sk);

			log_printfs(&e.skey, "[+] registering socket ");
			log_printf("so_cookie=0x%lx app=%d gen=%d pid=%d\n", s->so_cookie,
				   s->sock_app, s->sock_gen, ts->pid);

			unsigned ll = offsetof(struct msg_value, socket_app) + 8;
			int r = bpf_ringbuf_output(&msg_rb, &e, ll, 0);
			if (r != 0) {
				log_printf("[!] Error: rb failed, EGAIN\n");
				// We don't incr critical metric as we return EGAIN
				bpf_set_retval(-EAGAIN);
				return 0;
			}
		}
		ctx->optlen = -1;
		bpf_set_retval(0);
		return 1;
	}

	if (ctx->optname == UDP_GRM_DISSECTOR) {
		if (created == 0) {
			// reuseport group exists and is confirmed, check if user wants
			// to modify it
			if (dissector_cmp(&state->dis, &data->dis) != 0) {
				bpf_set_retval(-EPERM);
				return 0;
			} else {
				state->verbose = !!(data->dis.dissector_type &
						    DISSECTOR_FLAG_VERBOSE);
				// noop, nothing changed
				ctx->optlen = -1;
				bpf_set_retval(0);
				return 1;
			}
		}
		int fail = 0;
		switch (data->dis.dissector_type & ~DISSECTOR_FLAGS) {
		case DISSECTOR_FLOW:
			if (data->dis.filter_len != 0 || data->dis.max_apps != 0 ||
			    data->dis.bespoke_digest != 0) {
				fail = 1;
			}
			break;
		case DISSECTOR_CBPF:
			if (data->dis.filter_len < 1 ||
			    data->dis.filter_len > MAX_INSTR ||
			    data->dis.max_apps > MAX_APPS ||
			    data->dis.bespoke_digest != 0) {
				fail = 1;
			}
			break;
		case DISSECTOR_BESPOKE:
			/* Digest - zero filter_len and nonzero bespoke_digest */
			if (data->dis.filter_len == 0 && data->dis.bespoke_digest != 0) {
				fail = 0;
			}
			break;
		case DISSECTOR_NOOP:
			if (data->dis.filter_len != 0 || data->dis.max_apps != 0 ||
			    data->dis.bespoke_digest != 0) {
				fail = 1;
			}
			break;
		default: {
			fail = 1;
			break;
		}
		}
		if (fail) {
			if (created) {
				struct reuseport_storage_key skey;
				_skey_from_bpf_sock(&skey, ctx->sk);
				bpf_map_delete_elem(&reuseport_storage_map, &skey);
			}
			bpf_set_retval(-EPERM);
			return 0;
		}

		memcpy(&state->dis, &data->dis, sizeof(struct udp_grm_dissector));
		state->verbose = !!(data->dis.dissector_type & DISSECTOR_FLAG_VERBOSE);
		state->dis.dissector_type = data->dis.dissector_type & ~DISSECTOR_FLAGS;

		static struct msg_value e;
		e.type = MSG_SET_DISSECTOR;
		e.value = 0;
		_skey_from_bpf_sock(&e.skey, ctx->sk);

		log_printfs(&e.skey, "[+] setting dissector type %d\n",
			   DISSECTOR_TYPE(data->dis.dissector_type));

		unsigned ll = offsetof(struct msg_value, value) + 8;
		int r = bpf_ringbuf_output(&msg_rb, &e, ll, 0);
		if (r != 0) {
			log_printf("[!] Error: rb failed: EGAIN\n");
			// We don't incr critical metric as we return EGAIN
			bpf_set_retval(-EAGAIN);
			return 0;
		}

		ctx->optlen = -1;
		bpf_set_retval(0);
		return 1;
	}

	if (ctx->optname == UDP_GRM_FLOW_ASSURE) {
		if (DISSECTOR_TYPE(state->dis.dissector_type) != DISSECTOR_FLOW) {
			bpf_set_retval(-EPERM);
			return 0;
		}

		struct ip_flow_hash flow = {};
		flow.reuseport_group_id = state->random_id;

		switch (data->sin.sin_family) {
		case AF_INET:
			flow.remote_port = data->sin.sin_port;
			memcpy(flow.remote_ip, &data->sin.sin_addr, 4);
			break;
		case AF_INET6:
			flow.remote_port = data->sin6.sin6_port;
			memcpy(flow.remote_ip, &data->sin6.sin6_addr, 16);
			break;
		default:
			bpf_set_retval(-EPERM);
			return 0;
		}
		uint32_t hash = count_ip_flow_hash(&flow);
		int r = flow_assure(state, s, hash);
		if (r == 0) {
			bpf_set_retval(-EEXIST);
			return 0;
		}
		ctx->optlen = -1;
		bpf_set_retval(0);
		return 1;
	}

	if (ctx->optname == UDP_GRM_SOCKET_APP) {
		if (s->sock_app != data->value) {
			if (s->sock_gen != 0xffffffff || s->sock_idx != 0xffffffff) {
				bpf_set_retval(-EEXIST);
				return 0;
			}
			if (data->value >= state->dis.max_apps) {
				bpf_set_retval(-EOVERFLOW);
				return 0;
			}
			s->sock_app = data->value;
		}
		ctx->optlen = -1;
		bpf_set_retval(0);
		return 1;
	}

	/* Keep the reference to the maps in this function. This is
	 * needed to access the maps from userspace helper.*/
	asm("" ::"r"(&sockhash));
	asm("" ::"r"(&lru_map));
	asm("" ::"r"(&metrics_map));

	bpf_set_retval(-EPERM);
	return 0;
}

SEC("cgroup/getsockopt")
int udpgrm_getsockopt(struct bpf_sockopt *ctx)
{
	if (!(ctx->level == IPPROTO_UDP && ctx->optname >= _UDP_GRM_MIN &&
	      ctx->optname <= _UDP_GRM_MAX)) {
		/* Pass-thru */
		if (ctx->optlen > 4096)
			ctx->optlen = 0;
		return 1;
	}

	/* What if we have more than one bpf getsockopt hook running?
	 * getsockopt hook runs _after_ the kernel implementation, so
	 * we can assume retval==-92 which is ENOPROTOOPT. If retval
	 * is different, it clearly means someone else handled the
	 * call.
	 */
	if (bpf_get_retval() != -ENOPROTOOPT) {
		return 1;
	}

	/* Workarond for: error: Looks like the BPF stack limit of 512
	 * bytes is exceeded. Please move large on stack variables
	 * into BPF per-cpu array map. */
	/* Sanity check that we didn't overshoot the percpu_page */
	union setsockopt_opts *data = empty_percpu_page();
	if (data == NULL || sizeof(union setsockopt_opts) > PERCPU_ARRAY_SIZE) {
		bpf_set_retval(-ENOBUFS);
		return 0;
	}

	if (ctx->optname == UDP_GRM_WORKING_GEN) {
		/* According to the API contract, this should not
		 * error if udpgm is loaded. This can be used to check
		 * if udpgm is loaded. */
		struct reuseport_storage *state = get_state(ctx->sk, 0, NULL);
		if (state == NULL) {
			/* -1 means: no reuseport group yet. Also
			 * default working generation. */
			data->wrk.working_gen = (uint32_t)-1;
		} else {
			uint32_t app_idx;
			struct socket_storage *s =
				bpf_sk_storage_get(&sk_storage_map, ctx->sk, 0, 0);
			if (s == NULL) {
				app_idx = 0;
			} else {
				app_idx = s->sock_app;
			}
			data->wrk.working_gen = state->working_gen[app_idx % MAX_APPS];
		}
	} else if (ctx->optname == UDP_GRM_SOCKET_GEN) {
		struct socket_storage *s =
			bpf_sk_storage_get(&sk_storage_map, ctx->sk, 0, 0);
		if (s == NULL) {
			bpf_set_retval(-EBADFD);
			return 0;
		}

		data->sk.socket_gen = s->sock_gen;
		data->sk.socket_idx = s->sock_idx;

		uint32_t xmax_apps = 0;
		struct reuseport_storage *state = get_state(ctx->sk, 0, NULL);
		if (state != NULL) {
			xmax_apps = state->dis.max_apps;
		}

		uint32_t gen = TO_WRK_GEN(xmax_apps, s->sock_app, s->sock_gen);
		uint8_t v[4];
		grm_cookie_pack(gen, s->sock_idx, v);
		memcpy(&data->sk.grm_cookie, v, 4);
	} else if (ctx->optname == UDP_GRM_DISSECTOR) {
		struct reuseport_storage *state = get_state(ctx->sk, 0, NULL);
		if (state == NULL) {
			bpf_set_retval(-EBADFD);
			return 0;
		}

		memcpy(&data->dis, &state->dis, sizeof(struct udp_grm_dissector));
	} else if (ctx->optname == UDP_GRM_SOCKET_APP) {
		struct socket_storage *s =
			bpf_sk_storage_get(&sk_storage_map, ctx->sk, 0, 0);
		if (s == NULL) {
			bpf_set_retval(-EBADFD);
			return 0;
		}

		data->value = s->sock_app;
	} else {
		bpf_set_retval(-EPERM);
		return 0;
	}

	/* Careful memcpy dance to avoid upsetting the fragile verfier. */
	uint8_t *optval_end = (uint8_t *)ctx->optval_end;
	uint8_t *optval = (uint8_t *)ctx->optval;
	if (optval + sizeof(union setsockopt_opts) <= optval_end) {
		memcpy(optval, data, sizeof(union setsockopt_opts));
	} else if (optval + 116 + 4 + 256 <= optval_end) {
		memcpy(optval, data, 116 + 4 + 256);
	} else if (optval + 116 <= optval_end) {
		memcpy(optval, data, 116);
	} else if (optval + 16 <= optval_end) {
		memcpy(optval, data, 16);
	} else if (optval + 12 <= optval_end) {
		memcpy(optval, data, 12);
	} else if (optval + 8 <= optval_end) {
		memcpy(optval, data, 8);
	} else if (optval + 4 <= optval_end) {
		memcpy(optval, data, 4);
	} else {
		bpf_set_retval(-EFAULT);
		return 0;
	}

	bpf_set_retval(0);
	return 1;
}

int _bpf_bind(struct bpf_sock_addr *ctx);
SEC("cgroup/bind6")
int udpgrm_bpf_bind6(struct bpf_sock_addr *ctx) { return _bpf_bind(ctx); }
SEC("cgroup/bind4")
int udpgrm_bpf_bind4(struct bpf_sock_addr *ctx) { return _bpf_bind(ctx); }

/* In bind() we need to create sk_storage because here we have socket
 * cookie. In setsockopt context bpf_get_socket_cookie() doesn't
 * work. Socket state should be relatively lightweight. */
int _bpf_bind(struct bpf_sock_addr *ctx)
{
	if (ctx->user_family != AF_INET && ctx->user_family != AF_INET6) {
		return 1;
	}
	if (ctx->protocol != IPPROTO_UDP) {
		return 1;
	}

	int reuseport;
	int r = bpf_getsockopt(ctx, SOL_SOCKET, SO_REUSEPORT, &reuseport,
			       sizeof(reuseport));
	if (r != 0) {
		return 1;
	}
	if (reuseport == 0) {
		return 1;
	}

	struct socket_storage *s = bpf_sk_storage_get(&sk_storage_map, ctx->sk, 0,
						      BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (s == NULL) {
		log_printf("[!] Socket storage create failed\n");
		return 1;
	}

	s->sock_gen = -1;
	s->sock_idx = -1;
	s->so_cookie = bpf_get_socket_cookie(ctx);
	s->netns_cookie = bpf_get_netns_cookie(ctx);
	return 1;
}

static int flow_assure(struct reuseport_storage *state, struct socket_storage *s,
		       uint32_t hash)
{
	METRIC_INC(tx_total);

	struct lru_key key = {.rx_hash = hash};
	struct lru_value *value = bpf_map_lookup_elem(&lru_map, &key);
	if (value == NULL) {
		if (state->verbose)
			log_printf("[ ] hash=#%x new so_cookie=0x%x\n", hash,
				   s->so_cookie);
		struct lru_value val = {.last_tx_ns = bpf_ktime_get_ns(),
					.cookie = s->so_cookie};
		int r = bpf_map_update_elem(&lru_map, &key, &val, BPF_NOEXIST);
		if (r == 0) {
			METRIC_INC(tx_flow_create_ok);
		} else {
			// No slot can be created, or conflict. Is
			// insertion failure even possible in LRU
			// case?
			METRIC_INC(tx_flow_create_error);
			return 0;
		}
	} else {
		uint32_t flow_entry_timeout_sec = state->dis.flow_entry_timeout_sec;
		if (flow_entry_timeout_sec == 0)
			flow_entry_timeout_sec = FLOW_DEFAULT_TIMEOUT_SEC;

		if (state->verbose)
			log_printf("[ ] hash=#%x confirmed so_cookie=0x%x\n", hash,
				   s->so_cookie);
		uint64_t now = bpf_ktime_get_ns();
		if (now - value->last_tx_ns <= SEC_TO_NSEC(flow_entry_timeout_sec)) {
			// Not expired
			if (value->cookie == s->so_cookie) {
				METRIC_INC(tx_flow_update_ok);
				value->last_tx_ns = now;
			} else {
				// flow entry update conflict
				METRIC_INC(tx_flow_update_conflict);
				return 0;
			}
		} else {
			METRIC_INC(tx_flow_create_ok);
			METRIC_INC(tx_flow_create_from_expired_ok);
			// Expired
			value->last_tx_ns = bpf_ktime_get_ns();
			// Attempt to set memory barrier. First
			// timestamp, then cookie.
			asm volatile("" ::: "memory");
			value->cookie = s->so_cookie;
		}
	}
	return 1;
}

static int _udp_sendmsg(struct bpf_sock_addr *ctx, int family);

SEC("cgroup/sendmsg6")
int udpgrm_udp6_sendmsg(struct bpf_sock_addr *ctx) { return _udp_sendmsg(ctx, AF_INET6); }

SEC("cgroup/sendmsg4")
int udpgrm_udp4_sendmsg(struct bpf_sock_addr *ctx) { return _udp_sendmsg(ctx, AF_INET); }

static int _udp_sendmsg(struct bpf_sock_addr *ctx, int family)
{
	struct reuseport_storage *state = get_state(ctx->sk, 0, NULL);
	if (state == NULL)
		return 1;

	if (DISSECTOR_TYPE(state->dis.dissector_type) != DISSECTOR_FLOW)
		return 1;

	uint32_t hash = 0;

	/* The only possible */
	switch (DISSECTOR_TYPE(state->dis.dissector_type)) {
	case DISSECTOR_FLOW: {
		struct ip_flow_hash flow = {};
		flow.reuseport_group_id = state->random_id;
		flow.remote_port = ctx->user_port;
		switch (family) {
		case AF_INET:
			flow.remote_ip[0] = ctx->user_ip4;
			break;
		case AF_INET6:
			flow.remote_ip[0] = ctx->user_ip6[0];
			flow.remote_ip[1] = ctx->user_ip6[1];
			flow.remote_ip[2] = ctx->user_ip6[2];
			flow.remote_ip[3] = ctx->user_ip6[3];
			break;
		}
		hash = count_ip_flow_hash(&flow);
		break;
	}
	}

	struct socket_storage *s = bpf_sk_storage_get(&sk_storage_map, ctx->sk, 0, 0);
	if (s == NULL)
		return 1;

	flow_assure(state, s, hash);
	return 1;
}

SEC("tc")
int udpgrm_cb_update_map(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	struct msg_value *msg = (struct msg_value *)(data);
	if (msg + 1 > (struct msg_value *)data_end) {
		return 1;
	}
	msg = (struct msg_value *)(long)skb->data;

	struct reuseport_storage *state =
		bpf_map_lookup_elem(&reuseport_storage_map, &msg->skey);
	if (state == NULL) {
		return 1;
	}

	if (msg->type == GSM_SET_COOKIES) {
		state->cookies[msg->sock_gen % MAX_GENS]
			      [msg->sock_idx % MAX_SOCKETS_IN_GEN] = msg->sock_cookie;
		state->max_idx[msg->sock_gen % MAX_GENS] = msg->sock_gen_len;
	} else if (msg->type == GSM_SET_SOCKET_CRITICAL_GAUGE) {
		__sync_fetch_and_add(&state->socket_critical_gauge, msg->value);
	} else if (msg->type == GSM_INCR_SOCKET_CRITICAL) {
		__sync_fetch_and_add(&state->socket_critical, msg->value);
	} else {
		return 1;
	}

	return 0;
}
