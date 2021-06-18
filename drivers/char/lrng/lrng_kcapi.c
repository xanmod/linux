// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Backend for the LRNG providing the cryptographic primitives using the
 * kernel crypto API.
 *
 * Copyright (C) 2018 - 2021, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/hash.h>
#include <crypto/rng.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/lrng.h>

#include "lrng_kcapi_hash.h"

static char *drng_name = NULL;
module_param(drng_name, charp, 0444);
MODULE_PARM_DESC(drng_name, "Kernel crypto API name of DRNG");

static char *pool_hash = "sha512";
module_param(pool_hash, charp, 0444);
MODULE_PARM_DESC(pool_hash,
		 "Kernel crypto API name of hash or keyed message digest to read the entropy pool");

static char *seed_hash = NULL;
module_param(seed_hash, charp, 0444);
MODULE_PARM_DESC(seed_hash,
		 "Kernel crypto API name of hash with output size equal to seedsize of DRNG to bring seed string to the size required by the DRNG");

struct lrng_drng_info {
	struct crypto_rng *kcapi_rng;
	void *lrng_hash;
};

static void *lrng_kcapi_drng_hash_alloc(void)
{
	return lrng_kcapi_hash_alloc(pool_hash);
}

static int lrng_kcapi_drng_seed_helper(void *drng, const u8 *inbuf,
				       u32 inbuflen)
{
	SHASH_DESC_ON_STACK(shash, NULL);
	struct lrng_drng_info *lrng_drng_info = (struct lrng_drng_info *)drng;
	struct crypto_rng *kcapi_rng = lrng_drng_info->kcapi_rng;
	void *hash = lrng_drng_info->lrng_hash;
	u32 digestsize = lrng_kcapi_hash_digestsize(hash);
	u8 digest[HASH_MAX_DIGESTSIZE] __aligned(8);
	int ret;

	if (!hash)
		return crypto_rng_reset(kcapi_rng, inbuf, inbuflen);

	ret = lrng_kcapi_hash_init(shash, hash) ?:
	      lrng_kcapi_hash_update(shash, inbuf, inbuflen) ?:
	      lrng_kcapi_hash_final(shash, digest);
	lrng_kcapi_hash_zero(shash);
	if (ret)
		return ret;

	ret = crypto_rng_reset(kcapi_rng, digest, digestsize);
	if (ret)
		return ret;

	memzero_explicit(digest, digestsize);
	return 0;
}

static int lrng_kcapi_drng_generate_helper(void *drng, u8 *outbuf,
					   u32 outbuflen)
{
	struct lrng_drng_info *lrng_drng_info = (struct lrng_drng_info *)drng;
	struct crypto_rng *kcapi_rng = lrng_drng_info->kcapi_rng;
	int ret = crypto_rng_get_bytes(kcapi_rng, outbuf, outbuflen);

	if (ret < 0)
		return ret;

	return outbuflen;
}

static void *lrng_kcapi_drng_alloc(u32 sec_strength)
{
	struct lrng_drng_info *lrng_drng_info;
	struct crypto_rng *kcapi_rng;
	int seedsize;
	void *ret =  ERR_PTR(-ENOMEM);

	if (!drng_name) {
		pr_err("DRNG name missing\n");
		return ERR_PTR(-EINVAL);
	}

	if (!memcmp(drng_name, "drbg", 4) ||
	    !memcmp(drng_name, "stdrng", 6) ||
	    !memcmp(drng_name, "jitterentropy_rng", 17)) {
		pr_err("Refusing to load the requested random number generator\n");
		return ERR_PTR(-EINVAL);
	}

	lrng_drng_info = kmalloc(sizeof(*lrng_drng_info), GFP_KERNEL);
	if (!lrng_drng_info)
		return ERR_PTR(-ENOMEM);

	kcapi_rng = crypto_alloc_rng(drng_name, 0, 0);
	if (IS_ERR(kcapi_rng)) {
		pr_err("DRNG %s cannot be allocated\n", drng_name);
		ret = ERR_CAST(kcapi_rng);
		goto free;
	}
	lrng_drng_info->kcapi_rng = kcapi_rng;

	seedsize =  crypto_rng_seedsize(kcapi_rng);

	if (sec_strength > seedsize)
		pr_info("Seedsize DRNG (%u bits) lower than security strength of LRNG noise source (%u bits)\n",
			crypto_rng_seedsize(kcapi_rng) * 8, sec_strength * 8);

	if (seedsize) {
		void *lrng_hash;

		if (!seed_hash) {
			switch (seedsize) {
			case 32:
				seed_hash = "sha256";
				break;
			case 48:
				seed_hash = "sha384";
				break;
			case 64:
				seed_hash = "sha512";
				break;
			default:
				pr_err("Seed size %d cannot be processed\n",
				       seedsize);
				goto dealloc;
			}
		}

		lrng_hash = lrng_kcapi_hash_alloc(seed_hash);
		if (IS_ERR(lrng_hash)) {
			ret = ERR_CAST(lrng_hash);
			goto dealloc;
		}

		if (seedsize != lrng_kcapi_hash_digestsize(lrng_hash)) {
			pr_err("Seed hash output size not equal to DRNG seed size\n");
			lrng_kcapi_hash_dealloc(lrng_hash);
			ret = ERR_PTR(-EINVAL);
			goto dealloc;
		}

		lrng_drng_info->lrng_hash = lrng_hash;

		pr_info("Seed hash %s allocated\n", seed_hash);
	} else {
		lrng_drng_info->lrng_hash = NULL;
	}

	pr_info("Kernel crypto API DRNG %s allocated\n", drng_name);

	return lrng_drng_info;

dealloc:
	crypto_free_rng(kcapi_rng);
free:
	kfree(lrng_drng_info);
	return ret;
}

static void lrng_kcapi_drng_dealloc(void *drng)
{
	struct lrng_drng_info *lrng_drng_info = (struct lrng_drng_info *)drng;
	struct crypto_rng *kcapi_rng = lrng_drng_info->kcapi_rng;

	crypto_free_rng(kcapi_rng);
	if (lrng_drng_info->lrng_hash)
		lrng_kcapi_hash_dealloc(lrng_drng_info->lrng_hash);
	kfree(lrng_drng_info);
	pr_info("DRNG %s deallocated\n", drng_name);
}

static const char *lrng_kcapi_drng_name(void)
{
	return drng_name;
}

static const char *lrng_kcapi_pool_hash(void)
{
	return pool_hash;
}

static const struct lrng_crypto_cb lrng_kcapi_crypto_cb = {
	.lrng_drng_name			= lrng_kcapi_drng_name,
	.lrng_hash_name			= lrng_kcapi_pool_hash,
	.lrng_drng_alloc		= lrng_kcapi_drng_alloc,
	.lrng_drng_dealloc		= lrng_kcapi_drng_dealloc,
	.lrng_drng_seed_helper		= lrng_kcapi_drng_seed_helper,
	.lrng_drng_generate_helper	= lrng_kcapi_drng_generate_helper,
	.lrng_hash_alloc		= lrng_kcapi_drng_hash_alloc,
	.lrng_hash_dealloc		= lrng_kcapi_hash_dealloc,
	.lrng_hash_digestsize		= lrng_kcapi_hash_digestsize,
	.lrng_hash_init			= lrng_kcapi_hash_init,
	.lrng_hash_update		= lrng_kcapi_hash_update,
	.lrng_hash_final		= lrng_kcapi_hash_final,
	.lrng_hash_desc_zero		= lrng_kcapi_hash_zero,
};

static int __init lrng_kcapi_init(void)
{
	return lrng_set_drng_cb(&lrng_kcapi_crypto_cb);
}
static void __exit lrng_kcapi_exit(void)
{
	lrng_set_drng_cb(NULL);
}

late_initcall(lrng_kcapi_init);
module_exit(lrng_kcapi_exit);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("Linux Random Number Generator - kernel crypto API DRNG backend");
