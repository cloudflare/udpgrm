/*
 * Part of the code adapted from bpf_dbg.c
 *
 * https://github.com/torvalds/linux/blob/master/tools/bpf/bpf_dbg.c
 *
 * Copyright 2013 Daniel Borkmann <borkmann@redhat.com>
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 */

#ifndef BPF_MOD
#define BPF_MOD 0x90
#endif
#ifndef BPF_XOR
#define BPF_XOR 0xa0
#endif

#define BPF_LDX_B (BPF_LDX | BPF_B)
#define BPF_LDX_W (BPF_LDX | BPF_W)
#define BPF_JMP_JA (BPF_JMP | BPF_JA)
#define BPF_JMP_JEQ (BPF_JMP | BPF_JEQ)
#define BPF_JMP_JGT (BPF_JMP | BPF_JGT)
#define BPF_JMP_JGE (BPF_JMP | BPF_JGE)
#define BPF_JMP_JSET (BPF_JMP | BPF_JSET)
#define BPF_ALU_ADD (BPF_ALU | BPF_ADD)
#define BPF_ALU_SUB (BPF_ALU | BPF_SUB)
#define BPF_ALU_MUL (BPF_ALU | BPF_MUL)
#define BPF_ALU_DIV (BPF_ALU | BPF_DIV)
#define BPF_ALU_MOD (BPF_ALU | BPF_MOD)
#define BPF_ALU_NEG (BPF_ALU | BPF_NEG)
#define BPF_ALU_AND (BPF_ALU | BPF_AND)
#define BPF_ALU_OR (BPF_ALU | BPF_OR)
#define BPF_ALU_XOR (BPF_ALU | BPF_XOR)
#define BPF_ALU_LSH (BPF_ALU | BPF_LSH)
#define BPF_ALU_RSH (BPF_ALU | BPF_RSH)
#define BPF_MISC_TAX (BPF_MISC | BPF_TAX)
#define BPF_MISC_TXA (BPF_MISC | BPF_TXA)
#define BPF_LD_B (BPF_LD | BPF_B)
#define BPF_LD_H (BPF_LD | BPF_H)
#define BPF_LD_W (BPF_LD | BPF_W)

#define MEMWORDS_MASK (BPF_MEMWORDS - 1)

struct bpf_regs {
	uint32_t R;
	uint32_t A;
	uint32_t X;
	uint32_t M[BPF_MEMWORDS];
};

struct interpret_ctx {
	struct sk_reuseport_md *md;
	struct reuseport_storage *state;
	int offset;

	struct bpf_regs r;
	int *retval;
	int retcode;

	uint32_t next_index;
};

#define extract_u32(md, off)                                                             \
	({                                                                               \
		uint32_t v;                                                              \
		int r = bpf_skb_load_bytes(md, c->offset + off, &v, 4);                  \
		if (r != 0) {                                                            \
			c->retcode = IERR_LOAD;                                          \
			return LOOP_BREAK;                                               \
		}                                                                        \
		bpf_ntohl(v);                                                            \
	})

#define extract_u16(md, off)                                                             \
	({                                                                               \
		uint16_t v;                                                              \
		int r = bpf_skb_load_bytes(md, c->offset + off, &v, 2);                  \
		if (r != 0) {                                                            \
			c->retcode = IERR_LOAD;                                          \
			return LOOP_BREAK;                                               \
		}                                                                        \
		bpf_ntohs(v);                                                            \
	})

#define extract_u8(md, off)                                                              \
	({                                                                               \
		uint8_t v;                                                               \
		int r = bpf_skb_load_bytes(md, c->offset + off, &v, 1);                  \
		if (r != 0) {                                                            \
			c->retcode = IERR_LOAD;                                          \
			return LOOP_BREAK;                                               \
		}                                                                        \
		(v);                                                                     \
	})

/* log_printf("off=%d+%d b=%x\n", c->offset, off, v);	\ */

/* Bytecode returns:
   -1 on PUSH/POP error (too long, too short stack)
   -2 failed to load bytes - too short packet?
   -3 finished without return opcode
   -4 unrecognized instruction
   0  program finished, retval filled with the 3-byte packed thing
 */
enum {
	IERR_OK = 0,
	IERR_STACK = -1,
	IERR_LOAD = -2,
	IERR_INSTREXCEEDED = -3,
	IERR_BADINSTR = -4,
	IERR_SANITY = -5,
	IERR_BADRETURNVALUE = -6,
};

#define LOOP_BREAK 1
#define LOOP_CONTINUE 0
static int _do_interpret_loop(uint32_t index, void *_ctx)
{
	struct interpret_ctx *c = _ctx;

	/* Workaround against ebpf limitation where we can't
	 * arbitrarily move index variable forward*/
	if (index < c->next_index)
		return LOOP_CONTINUE;

	if (index >= MAX_INSTR) {
		c->retcode = IERR_SANITY;
		return LOOP_BREAK;
	}
	struct sock_filter *f = &c->state->dis.filter[index];

	if (c->state->verbose > 0)
		log_printf("#%02d: (0x%02x, %d, %d, 0x%08x)\n", index, f->code, f->jt,
			   f->jf, f->k);

	struct bpf_regs *r = &c->r;
	uint32_t K = f->k;

	// Consider supporting SKF_NET_LL as
	// bpf_skb_load_bytes_relative(BPF_HDR_START_MAC) and SKF_NET_OFF as
	// bpf_skb_load_bytes_relative(BPF_HDR_START_NET)

	uint32_t off;
	switch (f->code) {
	case BPF_MISC_TAX:
		r->X = r->A;
		break;
	case BPF_MISC_TXA:
		r->A = r->X;
		break;
	case BPF_ST:
		r->M[K & MEMWORDS_MASK] = r->A;
		break;
	case BPF_STX:
		r->M[K & MEMWORDS_MASK] = r->X;
		break;
	case BPF_LD_W | BPF_ABS:
		r->A = extract_u32(c->md, K);
		break;
	case BPF_LD_H | BPF_ABS:
		switch (K) {
		case SKF_AD_OFF + SKF_AD_PROTOCOL:
			// Did I get the endianness right?
			// md->eth_protocol is in network byte order, and we expect
			// this to be like 0x800, so host endianness.
			r->A = bpf_ntohs(c->md->eth_protocol);
			break;
		default:
			r->A = extract_u16(c->md, K);
		}
		break;
	case BPF_LD_B | BPF_ABS:
		r->A = extract_u8(c->md, K);

		break;
	case BPF_LD_W | BPF_IND:
		off = r->X + K;
		r->A = extract_u32(c->md, off);
		break;
	case BPF_LD_H | BPF_IND:
		off = r->X + K;
		r->A = extract_u16(c->md, off);
		break;
	case BPF_LD_B | BPF_IND:
		off = r->X + K;
		r->A = extract_u8(c->md, off);
		break;
	case BPF_LDX_B | BPF_MSH:
		r->X = extract_u8(c->md, K);
		r->X = (r->X & 0xf) << 2;
		break;
	case BPF_LD_W | BPF_LEN:
	case BPF_LDX_W | BPF_LEN:
		/* Total packet length minus the UDP payload offset:
		 * UDP payload length */
		r->A = c->md->len - c->offset;
		break;
	case BPF_LD | BPF_IMM:
		/* This is also {0,0,0,K} code point. */
		r->A = K;
		break;
	case BPF_LDX | BPF_IMM:
		r->X = K;
		break;
	case BPF_LD | BPF_MEM:
		r->A = r->M[K & MEMWORDS_MASK];
		break;
	case BPF_LDX | BPF_MEM:
		r->X = r->M[K & MEMWORDS_MASK];
		break;
	case BPF_JMP_JA:
		c->next_index = 1 + index + K;
		break;
	case BPF_JMP_JGT | BPF_X:
		c->next_index = 1 + index + (r->A > r->X ? f->jt : f->jf);
		break;
	case BPF_JMP_JGT | BPF_K:
		c->next_index = 1 + index + (r->A > K ? f->jt : f->jf);
		break;
	case BPF_JMP_JGE | BPF_X:
		c->next_index = 1 + index + (r->A >= r->X ? f->jt : f->jf);
		break;
	case BPF_JMP_JGE | BPF_K:
		c->next_index = 1 + index + (r->A >= K ? f->jt : f->jf);
		break;
	case BPF_JMP_JEQ | BPF_X:
		c->next_index = 1 + index + (r->A == r->X ? f->jt : f->jf);
		break;
	case BPF_JMP_JEQ | BPF_K:
		c->next_index = 1 + index + (r->A == K ? f->jt : f->jf);
		break;
	case BPF_JMP_JSET | BPF_X:
		c->next_index = 1 + index + (r->A & r->X ? f->jt : f->jf);
		break;
	case BPF_JMP_JSET | BPF_K:
		c->next_index = 1 + index + (r->A & K ? f->jt : f->jf);
		break;
	case BPF_ALU_NEG:
		r->A = -r->A;
		break;
	case BPF_ALU_LSH | BPF_X:
		r->A <<= r->X;
		break;
	case BPF_ALU_LSH | BPF_K:
		r->A <<= K;
		break;
	case BPF_ALU_RSH | BPF_X:
		r->A >>= r->X;
		break;
	case BPF_ALU_RSH | BPF_K:
		r->A >>= K;
		break;
	case BPF_ALU_ADD | BPF_X:
		r->A += r->X;
		break;
	case BPF_ALU_ADD | BPF_K:
		r->A += K;
		break;
	case BPF_ALU_SUB | BPF_X:
		r->A -= r->X;
		break;
	case BPF_ALU_SUB | BPF_K:
		r->A -= K;
		break;
	case BPF_ALU_MUL | BPF_X:
		r->A *= r->X;
		break;
	case BPF_ALU_MUL | BPF_K:
		r->A *= K;
		break;
	case BPF_ALU_DIV | BPF_X:
	case BPF_ALU_MOD | BPF_X:
		if (r->X == 0) {
			c->retcode = IERR_BADINSTR;
			return LOOP_BREAK;
		}
		goto do_div;
	case BPF_ALU_DIV | BPF_K:
	case BPF_ALU_MOD | BPF_K:
		if (K == 0) {
			c->retcode = IERR_BADINSTR;
			return LOOP_BREAK;
		}
	do_div:
		switch (f->code) {
		case BPF_ALU_DIV | BPF_X:
			r->A /= r->X;
			break;
		case BPF_ALU_DIV | BPF_K:
			r->A /= K;
			break;
		case BPF_ALU_MOD | BPF_X:
			r->A %= r->X;
			break;
		case BPF_ALU_MOD | BPF_K:
			r->A %= K;
			break;
		}
		break;
	case BPF_ALU_AND | BPF_X:
		r->A &= r->X;
		break;
	case BPF_ALU_AND | BPF_K:
		r->A &= K;
		break;
	case BPF_ALU_OR | BPF_X:
		r->A |= r->X;
		break;
	case BPF_ALU_OR | BPF_K:
		r->A |= K;
		break;
	case BPF_ALU_XOR | BPF_X:
		r->A ^= r->X;
		break;
	case BPF_ALU_XOR | BPF_K:
		r->A ^= K;
		break;

	case BPF_RET | BPF_K:
		c->retcode = IERR_OK;
		*c->retval = K;
		return LOOP_BREAK;
	case BPF_RET | BPF_X:
		c->retcode = IERR_OK;
		*c->retval = r->X;
		return LOOP_BREAK;
	case BPF_RET | BPF_A:
		c->retcode = IERR_OK;
		*c->retval = r->A;
		return LOOP_BREAK;
	default:
		c->retcode = IERR_BADINSTR;
		return LOOP_BREAK;
	}
	return LOOP_CONTINUE;
}

static int interpret_cbpf(struct sk_reuseport_md *md, struct reuseport_storage *state,
			  int *retval)
{
	struct interpret_ctx ctx = {
		.md = md,
		.state = state,
		.retval = retval,
		.retcode = IERR_INSTREXCEEDED, // exceeded instructions
		.offset = sizeof(struct udphdr),
	};
	bpf_loop(state->dis.filter_len, _do_interpret_loop, &ctx, 0);
	return ctx.retcode;
}
