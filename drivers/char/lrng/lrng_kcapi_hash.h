/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2020 - 2021, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _LRNG_KCAPI_HASH_H
#define _LRNG_KCAPI_HASH_H

#include <linux/module.h>

void *lrng_kcapi_hash_alloc(const char *name);
u32 lrng_kcapi_hash_digestsize(void *hash);
void lrng_kcapi_hash_dealloc(void *hash);
int lrng_kcapi_hash_init(struct shash_desc *shash, void *hash);
int lrng_kcapi_hash_update(struct shash_desc *shash, const u8 *inbuf,
			   u32 inbuflen);
int lrng_kcapi_hash_final(struct shash_desc *shash, u8 *digest);
void lrng_kcapi_hash_zero(struct shash_desc *shash);

#endif /* _LRNG_KCAPI_HASH_H */
