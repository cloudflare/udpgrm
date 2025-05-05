struct AES_ctx {
	uint8_t round_key[176];
};

#define AES_STATE_COLUMNS 4 // The number of columns comprising a state in AES.
#define AES_KEY_WORDS 4	    // The number of 32 bit words in a key.
#define AES_ROUND_COUNT 10  // The number of rounds in AES Cipher.

static const uint8_t aes_sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe,
	0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4,
	0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7,
	0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3,
	0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09,
	0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3,
	0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe,
	0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
	0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92,
	0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c,
	0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
	0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
	0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2,
	0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
	0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
	0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86,
	0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
	0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
	0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static const uint8_t round_constants[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
					    0x20, 0x40, 0x80, 0x1b, 0x36};

__attribute__((noinline)) int AES_key_expand(struct AES_ctx *restrict ctx,
					     const struct aes_key *restrict key)
{
	if (ctx == NULL || key == NULL)
		return -1;
	uint8_t *round_key = ctx->round_key;

	unsigned i, j, k;
	uint8_t tmp[4]; // Used for the column/row operations

#pragma unroll
	for (i = 0; i < AES_KEY_WORDS; ++i) {
		round_key[(i * 4) + 0] = key->u8[(i * 4) + 0];
		round_key[(i * 4) + 1] = key->u8[(i * 4) + 1];
		round_key[(i * 4) + 2] = key->u8[(i * 4) + 2];
		round_key[(i * 4) + 3] = key->u8[(i * 4) + 3];
	}

// increases stack on unroll
#pragma nounroll
	for (i = AES_KEY_WORDS; i < AES_STATE_COLUMNS * (AES_ROUND_COUNT + 1); ++i) {
		{
			k = (i - 1) * 4;
			tmp[0] = round_key[k + 0];
			tmp[1] = round_key[k + 1];
			tmp[2] = round_key[k + 2];
			tmp[3] = round_key[k + 3];
		}

		if (i % AES_KEY_WORDS == 0) {
			{
				const uint8_t u8tmp = tmp[0];
				tmp[0] = tmp[1];
				tmp[1] = tmp[2];
				tmp[2] = tmp[3];
				tmp[3] = u8tmp;
			}
			{
				tmp[0] = aes_sbox[tmp[0]];
				tmp[1] = aes_sbox[tmp[1]];
				tmp[2] = aes_sbox[tmp[2]];
				tmp[3] = aes_sbox[tmp[3]];
			}

			tmp[0] = tmp[0] ^ round_constants[i / AES_KEY_WORDS];
		}
		j = i * 4;
		k = (i - AES_KEY_WORDS) * 4;
		round_key[j + 0] = round_key[k + 0] ^ tmp[0];
		round_key[j + 1] = round_key[k + 1] ^ tmp[1];
		round_key[j + 2] = round_key[k + 2] ^ tmp[2];
		round_key[j + 3] = round_key[k + 3] ^ tmp[3];
	}
	return 0;
}

/* Ensure not inlined - reduces stack usage */
__attribute__((noinline)) int add_round_key(uint8_t round, struct aes_key *state,
					    const struct AES_ctx *ctx)
{
	if (state == NULL || ctx == NULL)
		return -1;
	if (round > AES_ROUND_COUNT)
		return -1;

	uint8_t i, j;
	for (i = 0; i < 4; ++i) {
		for (j = 0; j < 4; ++j) {
			uint8_t p = (round * AES_STATE_COLUMNS * 4) +
				    (i * AES_STATE_COLUMNS) + j;
			// this is never > 175 but hey, verifier has hard time.
			uint8_t x = ctx->round_key[p % 176];
			state->u8[(i * 4) + j] ^= x;
		}
	}
	return 0;
}

static void sub_bytes(struct aes_key *state)
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i) {
		for (j = 0; j < 4; ++j) {
			state->u8[(j * 4) + i] = aes_sbox[state->u8[(j * 4) + i]];
		}
	}
}

static void shift_rows(struct aes_key *state)
{
	uint8_t tmp;

	// Rotate first row 1 columns to left
	tmp = state->u8[(0 * 4) + 1];
	state->u8[(0 * 4) + 1] = state->u8[(1 * 4) + 1];
	state->u8[(1 * 4) + 1] = state->u8[(2 * 4) + 1];
	state->u8[(2 * 4) + 1] = state->u8[(3 * 4) + 1];
	state->u8[(3 * 4) + 1] = tmp;

	// Rotate second row 2 columns to left
	tmp = state->u8[(0 * 4) + 2];
	state->u8[(0 * 4) + 2] = state->u8[(2 * 4) + 2];
	state->u8[(2 * 4) + 2] = tmp;

	tmp = state->u8[(1 * 4) + 2];
	state->u8[(1 * 4) + 2] = state->u8[(3 * 4) + 2];
	state->u8[(3 * 4) + 2] = tmp;

	// Rotate third row 3 columns to left
	tmp = state->u8[(0 * 4) + 3];
	state->u8[(0 * 4) + 3] = state->u8[(3 * 4) + 3];
	state->u8[(3 * 4) + 3] = state->u8[(2 * 4) + 3];
	state->u8[(2 * 4) + 3] = state->u8[(1 * 4) + 3];
	state->u8[(1 * 4) + 3] = tmp;
}

#define gf_multiply_by_2(x) ((x << 1) ^ (((x >> 7) & 1) * 0x1b))

// MixColumns function mixes the columns of the state matrix
static int mix_columns(struct aes_key *state)
{
	uint8_t i;
	uint8_t tmp, tm;
// Unrolling this loop makes stack blow up from 32 to 256B
#pragma nounroll
	for (i = 0; i < 4; ++i) {
		const uint8_t t = state->u8[(i * 4) + 0];
		tmp = state->u8[(i * 4) + 0] ^ state->u8[(i * 4) + 1] ^
		      state->u8[(i * 4) + 2] ^ state->u8[(i * 4) + 3];
		tm = state->u8[(i * 4) + 0] ^ state->u8[(i * 4) + 1];
		tm = gf_multiply_by_2(tm);
		state->u8[(i * 4) + 0] ^= tm ^ tmp;
		tm = state->u8[(i * 4) + 1] ^ state->u8[(i * 4) + 2];
		tm = gf_multiply_by_2(tm);
		state->u8[(i * 4) + 1] ^= tm ^ tmp;
		tm = state->u8[(i * 4) + 2] ^ state->u8[(i * 4) + 3];
		tm = gf_multiply_by_2(tm);
		state->u8[(i * 4) + 2] ^= tm ^ tmp;
		tm = state->u8[(i * 4) + 3] ^ t;
		tm = gf_multiply_by_2(tm);
		state->u8[(i * 4) + 3] ^= tm ^ tmp;
	}
	return 0;
}

/* Costs 30k to inline */
__attribute__((noinline)) int AES_ECB_encrypt(const struct AES_ctx *restrict ctx,
					      struct aes_key *restrict state)
{
	if (ctx == NULL || state == NULL)
		return -1;

	uint8_t round = 0;

	add_round_key(0, state, ctx);
#pragma unroll
	for (round = 1;; ++round) {
		sub_bytes(state);
		shift_rows(state);
		if (round == AES_ROUND_COUNT) {
			break;
		}
		mix_columns(state);
		add_round_key(round, state, ctx);
	}
	add_round_key(AES_ROUND_COUNT, state, ctx);
	return 0;
}
