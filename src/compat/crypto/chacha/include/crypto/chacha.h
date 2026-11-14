/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Compatibility wrapper for kernels without the ChaCha library API.
 */

#ifndef _CRYPTO_CHACHA_H
#define _CRYPTO_CHACHA_H

#include <linux/string.h>
#include <zinc/chacha20.h>

#define CHACHA_IV_SIZE 16
#define CHACHA_KEY_SIZE CHACHA20_KEY_SIZE
#define CHACHA_BLOCK_SIZE CHACHA20_BLOCK_SIZE
#define CHACHAPOLY_IV_SIZE 12

static inline void chacha_init(u32 *state, const u32 *key, const u8 *iv)
{
	state[0] = CHACHA20_CONSTANT_EXPA;
	state[1] = CHACHA20_CONSTANT_ND_3;
	state[2] = CHACHA20_CONSTANT_2_BY;
	state[3] = CHACHA20_CONSTANT_TE_K;
	state[4] = key[0];
	state[5] = key[1];
	state[6] = key[2];
	state[7] = key[3];
	state[8] = key[4];
	state[9] = key[5];
	state[10] = key[6];
	state[11] = key[7];
	state[12] = get_unaligned_le32(iv + 0);
	state[13] = get_unaligned_le32(iv + 4);
	state[14] = get_unaligned_le32(iv + 8);
	state[15] = get_unaligned_le32(iv + 12);
}

static inline void chacha20_crypt(u32 *state, u8 *dst, const u8 *src,
				  unsigned int bytes)
{
	struct chacha20_ctx ctx;

	memcpy(ctx.state, state, sizeof(ctx.state));
	chacha20(&ctx, dst, src, bytes, DONT_USE_SIMD);
	memcpy(state, ctx.state, sizeof(ctx.state));
}

#endif /* _CRYPTO_CHACHA_H */
