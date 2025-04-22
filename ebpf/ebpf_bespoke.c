
#include "ebpf_quic.c"

/* Technically it's 26: 1 hdr, 4 version, 1 dcid len, 20 dcid */
#define MIN_QUIC_LEN 32

/* Always overshoots with DCID if it's not 20 bytes. Always just
 * copies 20 bytes. */
static int parse_quic_fast(struct sk_reuseport_md *md, struct dcid *dcid,
			   uint8_t *dcid_len_ptr, int *is_init_packet_ptr)
{
	if (dcid == NULL || dcid_len_ptr == NULL)
		return -1;

	uint8_t _packet[MIN_QUIC_LEN];

	uint8_t *pkt = md->data;
	uint8_t *pkt_end = md->data_end;
	/* Advance UDP header */
	pkt += 8;

	if (md->len < MIN_QUIC_LEN) {
		/* Packet too short */
		return IERR_SANITY;
	}

	if (pkt + MIN_QUIC_LEN > pkt_end) {
		/* Non-linear packet */
		int r = bpf_skb_load_bytes(md, 8, _packet, MIN_QUIC_LEN);
		if (r != 0)
			return IERR_LOAD;
		pkt = &_packet[0];
		pkt_end = &_packet[MIN_QUIC_LEN];
	}

	/* Fast path - check for is_long_header as fast as possible */
	uint8_t hdr = pkt[0];

	int is_long_header = hdr >> 7;
	int is_init_packet = (hdr >> 4) == 0xC;
	if (is_init_packet_ptr != NULL)
		*is_init_packet_ptr = is_init_packet;

	/* Fast path continues. Extract DCID. */
	if (is_long_header) {
		uint8_t dcid_len = pkt[1 + 4];
		if (dcid_len < 8 || dcid_len > 20)
			return IERR_SANITY;
		/* Ignore dcid_len, force 20 bytes */
		memcpy(dcid, &pkt[1 + 4 + 1], 20);

		size_t i;
		for (i = dcid_len; i < 20; i++) {
			dcid->u8[i] = 0;
			asm volatile("" : : : "memory");
		}

		if (dcid_len_ptr)
			*dcid_len_ptr = dcid_len;
	} else {
		/* No idea how long dcid really is */
		memcpy(dcid, &pkt[1], 20);
	}

	return IERR_OK;
}

#define x_memcmp(a, _b, l)                                                               \
	({                                                                               \
		const uint8_t b[] = _b;                                                  \
		int r = 0;                                                               \
		const size_t sz = sizeof(b) - 1;                                         \
		if (l != sz) {                                                           \
			r = 1;                                                           \
		} else {                                                                 \
			size_t i;                                                        \
			for (i = 0; i < sz; i++) {                                       \
				if (a[i] != b[i]) {                                      \
					r = 1;                                           \
					break;                                           \
				}                                                        \
			}                                                                \
		}                                                                        \
		(r);                                                                     \
	})

static int run_0xDEAD(struct sk_reuseport_md *md, struct reuseport_storage *state,
		      int *retval)
{
	if (state == NULL || retval == NULL)
		return IERR_SANITY;
	const uint8_t verbose = state->verbose;

	struct dcid dcid = {};
	uint8_t dcid_len = 0;
	uint8_t *sni = NULL;
	size_t sni_len = 0;
	int is_init_packet = 0;

	/* Four types of results:
	 *  - negative means hard error, most likely short packet
	 *  - zero AND sni means SNI found
	 *  - zero AND !sni means DCID found
	 */
	int r = parse_quic_fast(md, &dcid, &dcid_len, &is_init_packet);
	if (r != IERR_OK) {
		log_printf("[ ] Quic parse failed hard err=%d\n", r);
		return r;
	}
	if (verbose >= 3)
		log_printf_hex20("DCID", &dcid);

	if (is_init_packet) {
		/* This is slow path, parsing QUIC initial packet. This does
		 * AES decryption, and SHA, don't overoptimize this for
		 * speed. There is no need. */

		struct scratch *scratch = percpu_scratch_page();
		if (scratch == NULL) {
			return IERR_SANITY;
		}

		// Keys from DCID
		{
			/* DCID is copied to *tmp, then copy secret to scratch->secret */
			expand_client_keys_from_dcid(scratch, &dcid, dcid_len);
			if (verbose >= 4) {
				log_printf_hex16("quic_key", &scratch->quic_key);
				log_printf_hex16("quic_iv", &scratch->quic_iv);
				log_printf_hex16("quic_hp", &scratch->quic_hp);
			}
		}

		size_t enc_offset = 0, packet_len = 0;
		/* Initial packet, slow path */
		r = quic_parse_hdr(md, scratch, &enc_offset, &packet_len, verbose);
		/* IERR_LOAD - means problems with data load (perhaps wrong offsets?)
		 * IERR_SANITY - failed assumptions, like dcid>20
		 * IERR_BADINSTR - bad magic, like wrong quic version*/
		if (r != IERR_OK)
			return r;

		r = quic_extract_sni(md, scratch, enc_offset, packet_len, verbose);
		if (r == IERR_OK && scratch->sni_len) {
			sni = scratch->sni;
			sni_len = scratch->sni_len;
		} else if (r == IERR_OK) {
			if (verbose >= 1)
				log_printf(
					"[ ] Not a recognized crypto frame, or borken "
					"encryption\n");
		} else {
			if (verbose >= 1)
				log_printf("[ ] SNI failed %d\n", r);
		}
	}

	if (sni != NULL) {
		/* Advance SNI TLS extension header len */
		sni += 5;
		sni_len -= 5;
		(void)sni_len;

		if (verbose >= 2) {
			/* tmp make short for log */
			uint8_t x = sni[64];
			sni[64] = '\x00';
			if (verbose >= 2)
				log_printf("    SNI extracted: %s\n", sni);
			sni[64] = x;
		}

		uint32_t i;
		for (i = 0; i < MAX_BESPOKE_SNI; i++) {
			if (i >= state->dis.bespoke_hostname_len)
				break;
			/* Trunc at 61 bytes? */
			r = memcmp(sni, state->dis.bespoke_sni[i].hostname,
				   BESPOKE_SNI_LEN - 1);
			//			log_printf("r=%d\n");
			if (r == 0) {
				if (verbose >= 1)
					log_printf("[ ] SNI ok, app=1\n");
				*retval = 0x80000000ULL | state->dis.bespoke_sni[i].app;
				return IERR_OK;
			}
		}
		if (verbose >= 1)
			log_printf("[ ] SNI not matched, dispatching to app=0\n");
		*retval = 0x80000000ULL | 0x0;
		return IERR_OK;
	}

	/* Custom DCID */
	if (dcid.u8[0] == 1) {
		uint16_t cookie = *(uint16_t *)&dcid.u8[1];
		cookie = bswap16(cookie);
		if (cookie == 0) {
			uint8_t app = dcid.u8[4];
			if (verbose >= 1)
				log_printf("[ ] DCID by app %d\n", app);
			*retval = 0x80000000ULL | app;
		} else {
			if (verbose >= 1)
				log_printf("[ ] DCID by cookie %04x\n", cookie);
			*retval = cookie;
		}
		return IERR_OK;
	}
	if (verbose >= 1)
		log_printf("[ ] DCID not ours, dispatching to app=0\n");
	*retval = 0x80000000ULL | 0x0;
	return IERR_OK;
}

static int run_bespoke_by_digest(struct sk_reuseport_md *md, uint32_t bespoke_digest,
				 struct reuseport_storage *state, int *retval)
{
	(void)state;
	switch (bespoke_digest) {
	case 0xDEAD: {
		return run_0xDEAD(md, state, retval);
	}
	}

	return IERR_INSTREXCEEDED;
}
