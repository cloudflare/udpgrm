#define bswap64(q) __builtin_bswap64(q)
#define bswap32(q) __builtin_bswap32(q)
#define bswap16(q) __builtin_bswap16(q)

struct aes_key {
	uint8_t u8[16];
};

struct sha256_block {
	union {
		uint8_t u8[64];
		uint64_t u64[8];
	};
};

#include "ebpf_aes128.c"

#define log_printf_hex16(name, buf)                                                      \
	({                                                                               \
		const uint64_t *_tmp = (const uint64_t *)(buf);                          \
		log_printf("%10s %016llx%016llx\n", name, bswap64(_tmp[0]),              \
			   bswap64(_tmp[1]));                                            \
	})

#define log_printf_hex20(name, _buf)                                                     \
	({                                                                               \
		uint8_t *buf = (uint8_t *)_buf;                                          \
		log_printf("%10s %016llx%016llx%08x\n", name,                            \
			   bswap64(*(uint64_t *)&buf[0]), bswap64(*(uint64_t *)&buf[8]), \
			   bswap32(*(uint32_t *)&buf[16]));                              \
	})

/* We can try to squeeze it more, but does it make sense, if we need
 * at least 1KiB for decoded packet anways. */
struct scratch {
	union {
		/* First we use SHA */
		struct {
			/* Internal state for sha256 */
			uint32_t w[64];
			uint32_t tv[8];

			/* 64 bytes for sha256_hmac */
			struct sha256_block tmp;
			struct sha256_block secret;
		};

		/* Then we need aes_ctx */
		struct {
			struct AES_ctx aes_ctx;
		};

		/* Only later, we need SNI */
		struct {
			/* Extracted SNI */
			uint8_t sni[144 + 5 + 1];
			uint32_t sni_len;
		};
	};

	/* keys are needed in-between SHA */
	struct aes_key quic_key;
	struct aes_key quic_iv;
	struct aes_key quic_hp;

	/* Copy of packet header for non-linear packet, and decrypted packet later */
	uint8_t pkt[1024];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__uint(value_size, sizeof(struct scratch));
	__uint(max_entries, 1);
} percpu_sha_map SEC(".maps");

static void *percpu_scratch_page()
{
	int key = 0;
	return bpf_map_lookup_elem(&percpu_sha_map, &key);
}

#include "ebpf_sha256.c"

/* Mutates sample */
uint64_t compute_hp_mask(struct AES_ctx *ctx, struct aes_key *quic_hp,
			 struct aes_key *sample, uint8_t verbose)
{
	if (ctx == NULL || quic_hp == NULL || sample == NULL)
		return 0;

	memset(ctx, 0, sizeof(*ctx));

	// Initialize AES context with the header protection key
	AES_key_expand(ctx, quic_hp);

	// Encrypt the sample (ECB mode)
	AES_ECB_encrypt(ctx, sample);

	uint64_t mask = 0;
	// The mask is the first 5 bytes of the encrypted sample
	memcpy(&mask, &sample->u8[0], 5);

	if (verbose >= 3) {
		log_printf_hex16("aes_init", quic_hp);
		// log_printf_hex16("aes_enc", sample);
		log_printf_hex16("doneenc", sample);
	}

	return mask;
}

#define get_u8()                                                                         \
	({                                                                               \
		if (pkt + 1 > pkt_end) {                                                 \
			return IERR_LOAD;                                                \
		}                                                                        \
		uint8_t v = pkt[0];                                                      \
		pkt += 1;                                                                \
		(v);                                                                     \
	})

#define get_u16()                                                                        \
	({                                                                               \
		if (pkt + 2 > pkt_end)                                                   \
			return IERR_LOAD;                                                \
		uint16_t v = bswap16(*(uint16_t *)pkt);                                  \
		pkt += 2;                                                                \
		(v);                                                                     \
	})

#define get_u32()                                                                        \
	({                                                                               \
		if (pkt + 4 > pkt_end)                                                   \
			return IERR_LOAD;                                                \
		uint32_t v = bswap32(*(uint32_t *)pkt);                                  \
		pkt += 4;                                                                \
		(v);                                                                     \
	})
#define get_advance(off) ({ pkt += off; })

__attribute__((noinline)) int varint_decode(uint64_t data, uint64_t *value_ptr,
					    uint8_t *value_len_ptr)
{
	if (value_ptr == NULL || value_len_ptr == NULL)
		return -1;
	uint8_t *pkt = (uint8_t *)&data;
	switch (pkt[0] >> 6) {
	case 0:
		*value_ptr = pkt[0] & 0x3f;
		*value_len_ptr = 1;
		return 0;
	case 1:
		*value_ptr = bswap16(*(uint16_t *)pkt) & 0x3fffULL;
		*value_len_ptr = 2;
		return 0;
	case 2:
		*value_ptr = bswap32(*(uint32_t *)pkt) & 0x3fffffffULL;
		*value_len_ptr = 4;
		return 0;
	case 3:
		*value_ptr = bswap64(*(uint64_t *)pkt) & 0x3fffffffffffffffULL;
		*value_len_ptr = 8;
		return 0;
	}
	// never reached
	return -1;
}

static int increment_counter(struct aes_key *counter)
{
	if (counter == NULL)
		return 0;
	uint64_t *c = (void *)counter;
	/* Prefer branchless */
	c[1] = bswap64(bswap64(c[1]) + 1);
	c[0] = bswap64(bswap64(c[0]) + (c[1] == 0));
	return 0;
}

static int decrypt_quic_init(struct AES_ctx *ctx, struct aes_key *quic_key)
{
	AES_key_expand(ctx, quic_key);
	return 0;
}

struct _decrypt_quic_ctx {
	struct AES_ctx *aes_ctx;
	// scratch->quic_iv is counter
	struct scratch *scratch;
};

static int _do_decrypt_quic_loop(uint32_t index, void *_ctx)
{
	size_t i = index * 16;
	struct _decrypt_quic_ctx *ctx = _ctx;

	increment_counter(&ctx->scratch->quic_iv);
	struct aes_key tmp = ctx->scratch->quic_iv;

	AES_ECB_encrypt(ctx->aes_ctx, &tmp);
	if (i + 16 > sizeof(ctx->scratch->pkt))
		return LOOP_BREAK;

	uint8_t *pkt = &ctx->scratch->pkt[i];

	uint64_t *_p = (uint64_t *)pkt;
	uint64_t *_t = (uint64_t *)&tmp;
	_p[0] ^= _t[0];
	_p[1] ^= _t[1];

	return LOOP_CONTINUE;
}

/* Could be done branchless if anyone cares. */
static int clear_upper_bytes(uint64_t *_mask0, uint64_t *_mask1, uint8_t len)
{
	if (_mask0 == NULL || _mask1 == NULL)
		return -1;
	uint64_t mask_lo, mask_hi;

	// Clamp len to 0–16 just in case
	len &= 0x0F;

	if (len >= 8) {
		mask_lo = 0xFFFFFFFFFFFFFFFFULL;
		mask_hi = (1ULL << ((len - 8) * 8)) - 1;
	} else {
		mask_lo = (1ULL << (len * 8)) - 1;
		mask_hi = 0;
	}

	*_mask0 = mask_lo;
	*_mask1 = mask_hi;
	return 0;
}

/* No GCM validation. No true AE. Just decryption. No
 * authentication. In-place modify ctx, pkt and counter.
 * scratch->quic_iv is counter
 */
__attribute__((noinline)) int decrypt_quic(struct AES_ctx *aes_ctx,
					   struct scratch *scratch, size_t packet_len,
					   uint8_t verbose)
{
	if (scratch == NULL)
		return -1;
	if (aes_ctx == NULL)
		return -1;
	struct _decrypt_quic_ctx ctx = {.aes_ctx = aes_ctx, .scratch = scratch};
	(void)verbose;
	bpf_loop((packet_len / 16) + ((packet_len % 16) ? 1 : 0), _do_decrypt_quic_loop,
		 &ctx, 0);

	uint64_t mask0, mask1;
	clear_upper_bytes(&mask0, &mask1, packet_len % 16);
	size_t last_chunk_off = (packet_len / 16) * 16;
	/* Verifier requires this, like minus on right  */
	if (last_chunk_off > sizeof(scratch->pkt) - 16)
		return 0;
	*(uint64_t *)&scratch->pkt[last_chunk_off + 0] &= mask0;
	*(uint64_t *)&scratch->pkt[last_chunk_off + 8] &= mask1;

	return 0;
}

struct _do_print_ctx {
	struct scratch *scratch;
};

static int _do_print_loop(uint32_t index, void *_ctx)
{
	struct _do_print_ctx *ctx = _ctx;
	struct scratch *scratch = ctx->scratch;
	size_t i = index * 16;
	if (i + 16 > sizeof(scratch->pkt))
		return LOOP_BREAK;

	uint64_t *tmp = (uint64_t *)&scratch->pkt[i];
	log_printf("%10s %016llx%016llx\n", i == 0 ? "plaintext" : "", bswap64(tmp[0]),
		   bswap64(tmp[1]));
	return LOOP_CONTINUE;
}

static int log_print_plaintext(struct scratch *scratch, size_t packet_len)
{
	if (scratch == NULL)
		return 0;
	struct _do_print_ctx ctx = {.scratch = scratch};
	bpf_loop((packet_len / 16) + 1, _do_print_loop, &ctx, 0);
	return 0;
}

#define buf_get_u8()                                                                     \
	({                                                                               \
		if (buf_off + 1 > buf_sz)                                                \
			return IERR_LOAD;                                                \
		uint8_t v = buf[buf_off];                                                \
		buf_off += 1;                                                            \
		(v);                                                                     \
	})

#define buf_get_u16()                                                                    \
	({                                                                               \
		if (buf_off + 2 > buf_sz)                                                \
			return IERR_LOAD;                                                \
		uint16_t v = bswap16(*(uint16_t *)&buf[buf_off]);                        \
		buf_off += 2;                                                            \
		(v);                                                                     \
	})

#define buf_get_u32()                                                                    \
	({                                                                               \
		if (buf_off + 4 > buf_sz)                                                \
			return IERR_LOAD;                                                \
		uint32_t v = bswap32(*(uint32_t *)&buf[buf_off]);                        \
		buf_off += 4;                                                            \
		(v);                                                                     \
	})

#define buf_advance(off) ({ buf_off += off; })

/* Given decrypted Client-Hello packet in scratch->pkt, extract the
 * SNI, and copy it over to scratch->sni. Iterate over up to 32
 * extensions.
 *
 * IERR_OK on:
 *  - Not CRYPTO frame
 *  - SNI extracted fine
 *  - SNI not present in TLS
 */
static int parse_client_hello_extract_sni(struct scratch *scratch, uint8_t verbose)
{
	if (scratch == NULL)
		return IERR_SANITY;
	uint8_t *buf = &scratch->pkt[0];
	size_t buf_off = 0;
	const size_t buf_sz = sizeof(scratch->pkt);

	int r;

	uint8_t frame_type = buf_get_u8();
	if (frame_type != 0x6) {
		// not CRYPTO frame, is the frame sane?
		return IERR_OK;
	}

	uint64_t offset = 0;
	uint8_t offset_len;
	if (buf_off + 8 > buf_sz)
		return IERR_LOAD;
	r = varint_decode(*(uint64_t *)&buf[buf_off], &offset, &offset_len);
	if (r != 0)
		return IERR_LOAD;
	buf_advance(offset_len);

	uint64_t crypto_len = 0;
	uint8_t crypto_len_len;
	if (buf_off + 8 > buf_sz)
		return IERR_LOAD;
	r = varint_decode(*(uint64_t *)&buf[buf_off], &crypto_len, &crypto_len_len);
	if (r != 0)
		return IERR_LOAD;
	buf_advance(crypto_len_len);

	if (verbose >= 2)
		log_printf("TLS Frame %d offset=%lld crypto_len=%d\n", frame_type, offset,
			   crypto_len);

	uint8_t handshake_type = buf_get_u8();
	if (handshake_type != 0x1) // Client Hello
		return IERR_SANITY;
	uint32_t len = (buf_get_u8() << 16) | (buf_get_u8() << 8) | buf_get_u8();

	uint16_t client_version = buf_get_u16();
	buf_advance(32); // client random
	uint8_t session_id_len = buf_get_u8();
	if (verbose >= 2)
		log_printf("len=%d cv=%d sessid_len=%d\n", len, client_version,
			   session_id_len);
	buf_advance(session_id_len);
	uint16_t cipher_suite_len = buf_get_u16();

	buf_advance(cipher_suite_len);

	uint8_t compression_len = buf_get_u8();
	buf_advance(compression_len);

	uint16_t extensions_len = buf_get_u16();
	size_t extensions_end = buf_off + extensions_len;

	/* Hardcoded limit of up to 32 extensions parsed */
	int i;
	for (i = 0; i < 32; i++) {
		if (buf_off >= extensions_end)
			break;
		uint16_t ext_type = buf_get_u16();
		uint16_t ext_len = buf_get_u16();
		if (ext_type == 0) { // Server name, SNI
			/* Ensure we're not reading past buf */
			if (buf_off + sizeof(scratch->sni) > buf_sz)
				return IERR_LOAD;
			size_t i;
			for (i = 0; i < MIN(ext_len, sizeof(scratch->sni)); i++) {
				scratch->sni[i] = buf[buf_off + i];
			}
			scratch->sni_len = ext_len;
			return IERR_OK;
		}
		buf_advance(ext_len);
	}

	if (verbose >= 2)
		log_printf("TLS ct=%x version=%d \n", handshake_type, len);
	return IERR_OK;
}

enum {
	CONST_INITIAL_SALT,
	CONST_CLIENT_IN,
	CONST_QUIC_KEY,
	CONST_QUIC_IV,
	CONST_QUIC_HP,
};

/* Otherwise this is put on stack at 80 bytes */
__attribute__((noinline)) int load_const(struct sha256_block *tmp, int i)
{
	if (tmp == NULL)
		return 0;

	const uint8_t initial_salt[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34,
					  0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
					  0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};

	const uint8_t client_in[20] = "\x00\x20\x0ftls13 client in\x00\x01";

	const uint8_t quic_key[20] = "\0\x10\x0etls13 quic key\0\x01";
	const uint8_t quic_iv[20] = "\0\x0c\x0dtls13 quic iv\0\x01";
	const uint8_t quic_hp[20] = "\0\x10\x0dtls13 quic hp\0\x01";

	memset(&tmp->u8[20], 0, sizeof(*tmp) - 20);

	switch (i) {
	case CONST_INITIAL_SALT:
		memcpy(tmp, &initial_salt, sizeof(initial_salt));
		return 0;
	case CONST_CLIENT_IN:
		memcpy(tmp, &client_in, sizeof(client_in));
		return 0;
	case CONST_QUIC_KEY:
		memcpy(tmp, &quic_key, sizeof(quic_key));
		return 0;
	case CONST_QUIC_IV:
		memcpy(tmp, &quic_iv, sizeof(quic_iv));
		return 0;
	case CONST_QUIC_HP:
		memcpy(tmp, &quic_hp, sizeof(quic_hp));
		return 0;
	default:
		memset(tmp, 0, 20);
	}
	return 0;
}

struct dcid {
	uint8_t u8[20];
};

static int expand_client_keys_from_dcid(struct scratch *scratch,
					const struct dcid *user_dcid, uint8_t dcid_len)
{
	if (scratch == NULL || user_dcid == NULL)
		return -1;
	// tmp contains dcid
	struct sha256_block *tmp = &scratch->tmp;
	memset(tmp, 0, sizeof(*tmp));
	memcpy(tmp, user_dcid, 20);

	// initial_salt
	struct sha256_block *secret = &scratch->secret;
	load_const(secret, CONST_INITIAL_SALT);

	// initial_salt -> initial_secret
	sha256_hmac(scratch, secret, tmp, dcid_len);
	*secret = *tmp;

	// initial_secret -> client_initial_secret
	load_const(tmp, CONST_CLIENT_IN);
	sha256_hmac(scratch, secret, tmp, 20);
	*secret = *tmp;

	// client_initial_secret -> quic hp
	load_const(tmp, CONST_QUIC_HP);
	sha256_hmac(scratch, secret, tmp, 18);
	memcpy(&scratch->quic_hp, &tmp->u8, 16);

	// client_initial_secret -> quic key
	load_const(tmp, CONST_QUIC_KEY);
	sha256_hmac(scratch, secret, tmp, 19);
	memcpy(&scratch->quic_key, &tmp->u8, 16);

	// client_initial_secret -> quic iv
	load_const(tmp, CONST_QUIC_IV);
	sha256_hmac(scratch, secret, tmp, 18);
	memcpy(&scratch->quic_iv, &tmp->u8, 12);
	*(uint32_t *)&scratch->quic_iv.u8[12] = 0;
	return 0;
}

/*
 * IERR_OK - not initial packet or OK
 * IERR_LOAD - failed to read packet, most likely wrong offsets, or short packet
 * IERR_SANITY - failed assumptions, like dcid > 20, mostly for verifier
 * IERR_BADINSTR - quic version not 1
 */
static int quic_parse_hdr(struct sk_reuseport_md *md, struct scratch *scratch,
			  size_t *enc_offset_ptr, size_t *packet_len_ptr, uint8_t verbose)
{
	if (scratch == NULL) {
		return IERR_SANITY;
	}

	/* If packet not linear, copy first 256 bytes of packet to
	 * scratch area. We only need QUIC header, the payload will be
	 * copied anyway later for decryption. Typically this is less
	 * than 160 bytes:
	 *
	 * 8 UDP
	 * 1 quic hdr
	 * 4 quic version
	 * 1 DCID len
	 * 20 DCID
	 * 1 SCID len
	 * 20 SCID
	 * 1 token length
	 * 64 token (optional)
	 * 2 length
	 * 1 byte packet number
	 */
#define MIN_QUIC_HDR_LINEAR 192

	uint8_t *pkt = md->data;
	uint8_t *pkt_end = md->data_end;

	if (pkt_end - pkt < MIN(md->len, MIN_QUIC_HDR_LINEAR)) {
		pkt = scratch->pkt;
		size_t sz = md->len;
		if (sz < 1) {
			return IERR_SANITY;
		}
		if (sz > MIN_QUIC_HDR_LINEAR) {
			sz = MIN_QUIC_HDR_LINEAR;
		}
		int r = bpf_skb_load_bytes(md, 0, pkt, sz);
		if (r != 0) {
			return IERR_LOAD;
		}
		pkt_end = pkt + sz;
	}
	uint8_t *pkt_start = pkt;

	/* Pass UDP header */
	get_advance(8);

	uint8_t hdr = get_u8();
	int is_long_header = hdr >> 7;
	if ((hdr >> 4) != 0xC) {
		// Not initial packet, dispatch by DCID
		// This should be checked by parent function
		return IERR_OK;
	}

	// assume long quic packet
	uint32_t version = get_u32();
	if (version != 0x1) {
		/* Supported only quic version=1 */
		return IERR_BADINSTR;
	}
	uint8_t dcid_len = get_u8();
	if (dcid_len < 8 || dcid_len > 20)
		return IERR_SANITY;
	get_advance(dcid_len);

	{
		uint8_t scid_len = get_u8();
		// ignore scid
		get_advance(scid_len);
	}

	{
		uint64_t token_len = 0;
		uint8_t token_len_len;
		if (pkt + 8 > pkt_end)
			return IERR_LOAD;

		int r = varint_decode(*(uint64_t *)pkt, &token_len, &token_len_len);
		if (r != 0)
			return IERR_LOAD;

		// verifier
		if (token_len_len > 8 || token_len > 255)
			return IERR_SANITY;
		get_advance(token_len_len);
		get_advance(token_len);
	}

	size_t packet_len;
	{
		uint64_t _packet_len;
		uint8_t packet_len_len;
		if (pkt + 8 > pkt_end)
			return IERR_LOAD;
		int r = varint_decode(*(uint64_t *)pkt, &_packet_len, &packet_len_len);
		if (r != 0)
			return IERR_LOAD;

		// verifier
		if (packet_len_len > 255)
			return IERR_LOAD;
		get_advance(packet_len_len);
		// don't advance for remaider/encrypted/packet_len
		packet_len = _packet_len;
	}

	uint64_t hp_mask;
	{
		struct aes_key sample;
		if (pkt + 20 >= pkt_end)
			return IERR_LOAD;
		memcpy(&sample, pkt + 4, sizeof(sample));

		hp_mask = compute_hp_mask(&scratch->aes_ctx, &scratch->quic_hp, &sample,
					  verbose);
	}

	/* if (verbose >= 2) { */
	/* 	log_printf("hp_mask   %010llx  pno=%08x\n", bswap64(hp_mask) >> 24, */
	/* 		   bswap32(*(uint32_t *)&pkt[0])); */
	/* } */

	// Assuming little endian, lowest bits of hp_mask are the first byte indeed
	hdr ^= (hp_mask & 0xff) & (is_long_header ? 0x0F : 0x1F);

	/* Load 4 bytes, unmask */
	uint32_t pno = *(uint32_t *)pkt ^ (hp_mask >> 8);
	uint8_t pno_len = (hdr & 0x3) + 1;
	{
		/* if (verbose >= 2) { */
		/* 	log_printf("hdr=%02x pno_len=%d\n", hdr, pno_len); */
		/* } */

		switch (pno_len) {
		case 1:
			get_advance(1);
			pno &= 0xff;
			pno <<= 24;
			break;
		case 2:
			get_advance(2);
			pno &= 0xffff;
			pno <<= 16;
			break;
		case 3:
			get_advance(3);
			pno &= 0xffffff;
			pno <<= 8;
			break;
		case 4:
			get_advance(4);
			break;
		}
	}

	// Only after bswap32
	pno = bswap32(pno);

	// mutate iv to become nonce
	*(uint32_t *)&scratch->quic_iv.u8[8] ^= bswap32(pno);
	// mutate nonce to become counter
	*(uint32_t *)&scratch->quic_iv.u8[12] = bswap32(1);

	/* if (verbose >= 3) { */
	/* 	log_printf_hex16("counter", &scratch->quic_iv); */
	/* } */

	if (enc_offset_ptr)
		*enc_offset_ptr = pkt - pkt_start;
	/* strip pno and tag */
	if (packet_len_ptr)
		*packet_len_ptr = packet_len - pno_len - 16;

	return 0;
}

/* Scratch: we're using aes_key, quic_iv as counter, pkt for first
 * encrypte and then decrypted data. Then sni to store the estracted
 * server name extension. */
static int quic_extract_sni(struct sk_reuseport_md *md, struct scratch *scratch,
			    size_t enc_offset, size_t packet_len, uint8_t verbose)
{
	if (scratch == NULL)
		return -1;
	/* For decryption we need to access the packet in chunks of 16
	 * anyway. Easiest to just copy over the payload to
	 * scratch. */

	if (packet_len < 2)
		return IERR_SANITY;
	if (packet_len > sizeof(scratch->pkt))
		packet_len = sizeof(scratch->pkt);
	int r = bpf_skb_load_bytes(md, enc_offset, scratch->pkt, packet_len);
	if (r != 0)
		return IERR_LOAD;

	decrypt_quic_init(&scratch->aes_ctx, &scratch->quic_key);
	// &scratch->quic_iv is counter
	r = decrypt_quic(&scratch->aes_ctx, scratch, packet_len, verbose);
	if (r != IERR_OK)
		return r;
	if (verbose >= 2)
		log_print_plaintext(scratch, packet_len);

	memset(scratch->sni, 0, sizeof(scratch->sni));
	scratch->sni_len = 0;

	/* enc is in scratch, sni is in scratch */
	r = parse_client_hello_extract_sni(scratch, verbose);
	return r;
}
