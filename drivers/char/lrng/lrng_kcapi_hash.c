// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Backend for providing the hash primitive using the kernel crypto API.
 *
 * Copyright (C) 2021, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/hash.h>

#include "lrng_kcapi_hash.h"

struct lrng_hash_info {
	struct crypto_shash *tfm;
};

static inline void _lrng_kcapi_hash_free(struct lrng_hash_info *lrng_hash)
{
	struct crypto_shash *tfm = lrng_hash->tfm;

	crypto_free_shash(tfm);
	kfree(lrng_hash);
}

void *lrng_kcapi_hash_alloc(const char *name)
{
	struct lrng_hash_info *lrng_hash;
	struct crypto_shash *tfm;
	int ret;

	if (!name) {
		pr_err("Hash name missing\n");
		return ERR_PTR(-EINVAL);
	}

	tfm = crypto_alloc_shash(name, 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("could not allocate hash %s\n", name);
		return ERR_CAST(tfm);
	}

	ret = sizeof(struct lrng_hash_info);
	lrng_hash = kmalloc(ret, GFP_KERNEL);
	if (!lrng_hash) {
		crypto_free_shash(tfm);
		return ERR_PTR(-ENOMEM);
	}

	lrng_hash->tfm = tfm;

	pr_info("Hash %s allocated\n", name);

	return lrng_hash;
}
EXPORT_SYMBOL(lrng_kcapi_hash_alloc);

u32 lrng_kcapi_hash_digestsize(void *hash)
{
	struct lrng_hash_info *lrng_hash = (struct lrng_hash_info *)hash;
	struct crypto_shash *tfm = lrng_hash->tfm;

	return crypto_shash_digestsize(tfm);
}
EXPORT_SYMBOL(lrng_kcapi_hash_digestsize);

void lrng_kcapi_hash_dealloc(void *hash)
{
	struct lrng_hash_info *lrng_hash = (struct lrng_hash_info *)hash;

	_lrng_kcapi_hash_free(lrng_hash);
	pr_info("Hash deallocated\n");
}
EXPORT_SYMBOL(lrng_kcapi_hash_dealloc);

int lrng_kcapi_hash_init(struct shash_desc *shash, void *hash)
{
	struct lrng_hash_info *lrng_hash = (struct lrng_hash_info *)hash;
	struct crypto_shash *tfm = lrng_hash->tfm;

	shash->tfm = tfm;
	return crypto_shash_init(shash);
}
EXPORT_SYMBOL(lrng_kcapi_hash_init);

int lrng_kcapi_hash_update(struct shash_desc *shash, const u8 *inbuf,
			   u32 inbuflen)
{
	return crypto_shash_update(shash, inbuf, inbuflen);
}
EXPORT_SYMBOL(lrng_kcapi_hash_update);

int lrng_kcapi_hash_final(struct shash_desc *shash, u8 *digest)
{
	return crypto_shash_final(shash, digest);
}
EXPORT_SYMBOL(lrng_kcapi_hash_final);

void lrng_kcapi_hash_zero(struct shash_desc *shash)
{
	shash_desc_zero(shash);
}
EXPORT_SYMBOL(lrng_kcapi_hash_zero);
