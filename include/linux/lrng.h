/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2018 - 2021, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _LRNG_H
#define _LRNG_H

#include <crypto/hash.h>
#include <linux/errno.h>
#include <linux/types.h>

/**
 * struct lrng_crypto_cb - cryptographic callback functions
 * @lrng_drng_name		Name of DRNG
 * @lrng_hash_name		Name of Hash used for reading entropy pool
 * @lrng_drng_alloc:		Allocate DRNG -- the provided integer should be
 *				used for sanity checks.
 *				return: allocated data structure or PTR_ERR on
 *					error
 * @lrng_drng_dealloc:		Deallocate DRNG
 * @lrng_drng_seed_helper:	Seed the DRNG with data of arbitrary length
 *				drng: is pointer to data structure allocated
 *				      with lrng_drng_alloc
 *				return: >= 0 on success, < 0 on error
 * @lrng_drng_generate_helper:	Generate random numbers from the DRNG with
 *				arbitrary length
 * @lrng_hash_alloc:		Allocate the hash for reading the entropy pool
 *				return: allocated data structure (NULL is
 *					success too) or ERR_PTR on error
 * @lrng_hash_dealloc:		Deallocate Hash
 * @lrng_hash_digestsize:	Return the digestsize for the used hash to read
 *				out entropy pool
 *				hash: is pointer to data structure allocated
 *				      with lrng_hash_alloc
 *				return: size of digest of hash in bytes
 * @lrng_hash_init:		Initialize hash
 *				hash: is pointer to data structure allocated
 *				      with lrng_hash_alloc
 *				return: 0 on success, < 0 on error
 * @lrng_hash_update:		Update hash operation
 *				hash: is pointer to data structure allocated
 *				      with lrng_hash_alloc
 *				return: 0 on success, < 0 on error
 * @lrng_hash_final		Final hash operation
 *				hash: is pointer to data structure allocated
 *				      with lrng_hash_alloc
 *				return: 0 on success, < 0 on error
 * @lrng_hash_desc_zero		Zeroization of hash state buffer
 *
 * Assumptions:
 *
 * 1. Hash operation will not sleep
 * 2. The hash' volatile state information is provided with *shash by caller.
 */
struct lrng_crypto_cb {
	const char *(*lrng_drng_name)(void);
	const char *(*lrng_hash_name)(void);
	void *(*lrng_drng_alloc)(u32 sec_strength);
	void (*lrng_drng_dealloc)(void *drng);
	int (*lrng_drng_seed_helper)(void *drng, const u8 *inbuf, u32 inbuflen);
	int (*lrng_drng_generate_helper)(void *drng, u8 *outbuf, u32 outbuflen);
	void *(*lrng_hash_alloc)(void);
	void (*lrng_hash_dealloc)(void *hash);
	u32 (*lrng_hash_digestsize)(void *hash);
	int (*lrng_hash_init)(struct shash_desc *shash, void *hash);
	int (*lrng_hash_update)(struct shash_desc *shash, const u8 *inbuf,
				u32 inbuflen);
	int (*lrng_hash_final)(struct shash_desc *shash, u8 *digest);
	void (*lrng_hash_desc_zero)(struct shash_desc *shash);
};

/* Register cryptographic backend */
#ifdef CONFIG_LRNG_DRNG_SWITCH
int lrng_set_drng_cb(const struct lrng_crypto_cb *cb);
#else	/* CONFIG_LRNG_DRNG_SWITCH */
static inline int
lrng_set_drng_cb(const struct lrng_crypto_cb *cb) { return -EOPNOTSUPP; }
#endif	/* CONFIG_LRNG_DRNG_SWITCH */

#endif /* _LRNG_H */
