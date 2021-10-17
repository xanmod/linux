/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * LRNG ChaCha20 definitions
 *
 * Copyright (C) 2016 - 2021, Stephan Mueller <smueller@chronox.de>
 */

#include <crypto/chacha.h>

/* State according to RFC 7539 section 2.3 */
struct chacha20_block {
	u32 constants[4];
	union {
#define CHACHA_KEY_SIZE_WORDS (CHACHA_KEY_SIZE / sizeof(u32))
		u32 u[CHACHA_KEY_SIZE_WORDS];
		u8  b[CHACHA_KEY_SIZE];
	} key;
	u32 counter;
	u32 nonce[3];
};

static inline void lrng_cc20_init_rfc7539(struct chacha20_block *chacha20)
{
	chacha_init_consts(chacha20->constants);
}
