struct sha256_buff {
	uint32_t h[8];
};

static void sha256_init(struct sha256_buff *buff)
{
	buff->h[0] = 0x6a09e667;
	buff->h[1] = 0xbb67ae85;
	buff->h[2] = 0x3c6ef372;
	buff->h[3] = 0xa54ff53a;
	buff->h[4] = 0x510e527f;
	buff->h[5] = 0x9b05688c;
	buff->h[6] = 0x1f83d9ab;
	buff->h[7] = 0x5be0cd19;
}

static const uint32_t k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define ROTATE_R(val, bits) ((val) >> (bits) | (val) << (32 - (bits)))

/* ctx is changed, b is not changed */
/* must be noinline */
__attribute__((noinline)) int sha256_calc_chunk(struct scratch *restrict scratch,
						struct sha256_buff *restrict ctx,
						struct sha256_block *restrict b)
{
	if (ctx == NULL || b == NULL || scratch == NULL)
		return -1;
	uint32_t *chunk = (uint32_t *)b->u8;
	uint32_t *w = scratch->w;
	uint32_t *tv = scratch->tv;

	uint32_t i;

#pragma unroll
	for (i = 0; i < 16; ++i) {
		w[i] = bswap32(chunk[i]);
	}

#pragma unroll
	for (i = 16; i < 64; ++i) {
		uint32_t s0 = ROTATE_R(w[i - 15], 7) ^ ROTATE_R(w[i - 15], 18) ^
			      (w[i - 15] >> 3);
		uint32_t s1 = ROTATE_R(w[i - 2], 17) ^ ROTATE_R(w[i - 2], 19) ^
			      (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

#pragma unroll
	for (i = 0; i < 8; ++i)
		tv[i] = ctx->h[i];

// bumps stack with unroll
#pragma nounroll
	for (i = 0; i < 64; ++i) {
		uint32_t S1 =
			ROTATE_R(tv[4], 6) ^ ROTATE_R(tv[4], 11) ^ ROTATE_R(tv[4], 25);
		uint32_t ch = (tv[4] & tv[5]) ^ (~tv[4] & tv[6]);
		uint32_t temp1 = tv[7] + S1 + ch + k[i] + w[i];
		uint32_t S0 =
			ROTATE_R(tv[0], 2) ^ ROTATE_R(tv[0], 13) ^ ROTATE_R(tv[0], 22);
		uint32_t maj = (tv[0] & tv[1]) ^ (tv[0] & tv[2]) ^ (tv[1] & tv[2]);
		uint32_t temp2 = S0 + maj;

		tv[7] = tv[6];
		tv[6] = tv[5];
		tv[5] = tv[4];
		tv[4] = tv[3] + temp1;
		tv[3] = tv[2];
		tv[2] = tv[1];
		tv[1] = tv[0];
		tv[0] = temp1 + temp2;
	}

#pragma unroll
	for (i = 0; i < 8; ++i)
		ctx->h[i] += tv[i];
	return 0;
}

/* overwrites data */
static int sha256_final(struct scratch *scratch, struct sha256_buff *ctx,
			struct sha256_block *data, size_t data_len, int total_len)
{
	if (data == NULL)
		return -1;
	if (data_len < 0 || data_len > 55) {
		// NOT IMPL
		return -1;
	}
	data->u8[data_len] = 0x80;
	data_len += 1;

	uint64_t size = total_len * 8;
	*(uint64_t *)&data->u8[56] = bswap64(size);

	sha256_calc_chunk(scratch, ctx, data);
	return 0;
}

static void sha256_read(const struct sha256_buff *buff, uint8_t *hash)
{
	uint32_t i;
	uint32_t *h = (uint32_t *)hash;
	for (i = 0; i < 8; i++) {
		h[i] = bswap32(buff->h[i]);
	}
}

/* overwrites key and data */
/* Must be noinline. */
__attribute__((noinline)) int sha256_hmac(struct scratch *scratch,
					  struct sha256_block *key,
					  struct sha256_block *data, size_t data_len)
{
	if (key == NULL || data == NULL)
		return -1;

	size_t i;

	struct sha256_buff ctx;
	sha256_init(&ctx);

	// k_ipad
	for (i = 0; i < 8; i++)
		key->u64[i] ^= 0x3636363636363636ULL;
	sha256_calc_chunk(scratch, &ctx, key);

	// clear k_ipad, set k_opad
	for (i = 0; i < 8; i++)
		key->u64[i] ^= 0x3636363636363636ULL ^ 0x5c5c5c5c5c5c5c5cULL;

	sha256_final(scratch, &ctx, data, data_len, data_len + 64);
	memset(data->u8, 0, 64);
	sha256_read(&ctx, data->u8);

	sha256_init(&ctx);

	// already k_opad
	sha256_calc_chunk(scratch, &ctx, key);
	// clear k_opad
	for (i = 0; i < 8; i++)
		key->u64[i] ^= 0x5c5c5c5c5c5c5c5cULL;
	sha256_final(scratch, &ctx, data, 32, 32 + 64);
	memset(data->u8, 0, 64);
	sha256_read(&ctx, data->u8);
	return 0;
}
