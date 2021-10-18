// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * LRNG Fast Entropy Source: CPU-based entropy source
 *
 * Copyright (C) 2016 - 2021, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/hash.h>
#include <linux/lrng.h>
#include <linux/random.h>

#include "lrng_internal.h"

/*
 * Estimated entropy of data is a 32th of LRNG_DRNG_SECURITY_STRENGTH_BITS.
 * As we have no ability to review the implementation of those noise sources,
 * it is prudent to have a conservative estimate here.
 */
#define LRNG_ARCHRANDOM_DEFAULT_STRENGTH CONFIG_LRNG_CPU_ENTROPY_RATE
#define LRNG_ARCHRANDOM_TRUST_CPU_STRENGTH LRNG_DRNG_SECURITY_STRENGTH_BITS
#ifdef CONFIG_RANDOM_TRUST_CPU
static u32 archrandom = LRNG_ARCHRANDOM_TRUST_CPU_STRENGTH;
#else
static u32 archrandom = LRNG_ARCHRANDOM_DEFAULT_STRENGTH;
#endif
#ifdef CONFIG_LRNG_RUNTIME_ES_CONFIG
module_param(archrandom, uint, 0644);
MODULE_PARM_DESC(archrandom, "Entropy in bits of 256 data bits from CPU noise source (e.g. RDSEED)");
#endif

static int __init lrng_parse_trust_cpu(char *arg)
{
	int ret;
	bool trust_cpu = false;

	ret = kstrtobool(arg, &trust_cpu);
	if (ret)
		return ret;

	if (trust_cpu) {
		archrandom = LRNG_ARCHRANDOM_TRUST_CPU_STRENGTH;
		lrng_pool_add_entropy();
	} else {
		archrandom = LRNG_ARCHRANDOM_DEFAULT_STRENGTH;
	}

	return 0;
}
early_param("random.trust_cpu", lrng_parse_trust_cpu);

u32 lrng_archrandom_entropylevel(u32 requested_bits)
{
	return lrng_fast_noise_entropylevel(archrandom, requested_bits);
}

static u32 lrng_get_arch_data(u8 *outbuf, u32 requested_bits)
{
	u32 i;

	/* operate on full blocks */
	BUILD_BUG_ON(LRNG_DRNG_SECURITY_STRENGTH_BYTES % sizeof(unsigned long));
	BUILD_BUG_ON(CONFIG_LRNG_SEED_BUFFER_INIT_ADD_BITS %
							 sizeof(unsigned long));
	/* ensure we have aligned buffers */
	BUILD_BUG_ON(LRNG_KCAPI_ALIGN % sizeof(unsigned long));

	for (i = 0; i < (requested_bits >> 3);
	     i += sizeof(unsigned long)) {
		if (!arch_get_random_seed_long((unsigned long *)(outbuf + i)) &&
		    !arch_get_random_long((unsigned long *)(outbuf + i))) {
			archrandom = 0;
			return 0;
		}
	}

	return requested_bits;
}

static u32 inline lrng_get_arch_data_compress(u8 *outbuf, u32 requested_bits,
					      u32 data_multiplier)
{
	SHASH_DESC_ON_STACK(shash, NULL);
	const struct lrng_crypto_cb *crypto_cb;
	struct lrng_drng *drng = lrng_drng_init_instance();
	unsigned long flags;
	u32 ent_bits = 0, i, partial_bits = 0,
	    full_bits = requested_bits * data_multiplier;
	void *hash;

	/* Calculate oversampling for SP800-90C */
	if (lrng_sp80090c_compliant()) {
		/* Complete amount of bits to be pulled */
		full_bits += CONFIG_LRNG_OVERSAMPLE_ES_BITS * data_multiplier;
		/* Full blocks that will be pulled */
		data_multiplier = full_bits / requested_bits;
		/* Partial block in bits to be pulled */
		partial_bits = full_bits - (data_multiplier * requested_bits);
	}

	lrng_hash_lock(drng, &flags);
	crypto_cb = drng->crypto_cb;
	hash = drng->hash;

	if (crypto_cb->lrng_hash_init(shash, hash))
		goto out;

	/* Hash all data from the CPU entropy source */
	for (i = 0; i < data_multiplier; i++) {
		ent_bits = lrng_get_arch_data(outbuf, requested_bits);
		if (!ent_bits)
			goto out;

		if (crypto_cb->lrng_hash_update(shash, outbuf, ent_bits >> 3))
			goto err;
	}

	/* Hash partial block, if applicable */
	ent_bits = lrng_get_arch_data(outbuf, partial_bits);
	if (ent_bits &&
	    crypto_cb->lrng_hash_update(shash, outbuf, ent_bits >> 3))
		goto err;

	pr_debug("pulled %u bits from CPU RNG entropy source\n", full_bits);

	/* Generate the compressed data to be returned to the caller */
	ent_bits = crypto_cb->lrng_hash_digestsize(hash) << 3;
	if (requested_bits < ent_bits) {
		u8 digest[LRNG_MAX_DIGESTSIZE];

		if (crypto_cb->lrng_hash_final(shash, digest))
			goto err;

		/* Truncate output data to requested size */
		memcpy(outbuf, digest, requested_bits >> 3);
		memzero_explicit(digest, crypto_cb->lrng_hash_digestsize(hash));
		ent_bits = requested_bits;
	} else {
		if (crypto_cb->lrng_hash_final(shash, outbuf))
			goto err;
	}

out:
	crypto_cb->lrng_hash_desc_zero(shash);
	lrng_hash_unlock(drng, flags);
	return ent_bits;

err:
	ent_bits = 0;
	goto out;
}

/*
 * If CPU entropy source requires does not return full entropy, return the
 * multiplier of how much data shall be sampled from it.
 */
static u32 lrng_arch_multiplier(void)
{
	static u32 data_multiplier = 0;

	if (data_multiplier > 0) {
		return data_multiplier;
	} else {
		unsigned long v;

		if (IS_ENABLED(CONFIG_X86) && !arch_get_random_seed_long(&v)) {
			/*
			 * Intel SPEC: pulling 512 blocks from RDRAND ensures
			 * one reseed making it logically equivalent to RDSEED.
			 */
			data_multiplier = 512;
		} else if (IS_ENABLED(CONFIG_PPC)) {
			/*
			 * PowerISA defines DARN to deliver at least 0.5 bits of
			 * entropy per data bit.
			 */
			data_multiplier = 2;
		} else {
			/* CPU provides full entropy */
			data_multiplier = CONFIG_LRNG_CPU_FULL_ENT_MULTIPLIER;
		}
	}
	return data_multiplier;
}

/*
 * lrng_get_arch() - Get CPU entropy source entropy
 *
 * @outbuf: buffer to store entropy of size requested_bits
 *
 * Return:
 * * > 0 on success where value provides the added entropy in bits
 * *   0 if no fast source was available
 */
u32 lrng_get_arch(u8 *outbuf, u32 requested_bits)
{
	u32 ent_bits, data_multiplier = lrng_arch_multiplier();

	if (data_multiplier <= 1) {
		ent_bits = lrng_get_arch_data(outbuf, requested_bits);
	} else {
		ent_bits = lrng_get_arch_data_compress(outbuf, requested_bits,
						       data_multiplier);
	}

	ent_bits = lrng_archrandom_entropylevel(ent_bits);
	pr_debug("obtained %u bits of entropy from CPU RNG entropy source\n",
		 ent_bits);
	return ent_bits;
}

void lrng_arch_es_state(unsigned char *buf, size_t buflen)
{
	const struct lrng_drng *lrng_drng_init = lrng_drng_init_instance();
	u32 data_multiplier = lrng_arch_multiplier();

	/* Assume the lrng_drng_init lock is taken by caller */
	snprintf(buf, buflen,
		 "CPU ES properties:\n"
		 " Hash for compressing data: %s\n"
		 " Data multiplier: %u\n",
		 (data_multiplier <= 1) ?
			"N/A" : lrng_drng_init->crypto_cb->lrng_hash_name(),
		 data_multiplier);
}
