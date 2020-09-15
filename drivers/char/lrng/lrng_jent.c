// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * LRNG Fast Noise Source: Jitter RNG
 *
 * Copyright (C) 2016 - 2020, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/types.h>
#include <crypto/internal/jitterentropy.h>

#include "lrng_internal.h"

/*
 * Estimated entropy of data is a 16th of LRNG_DRNG_SECURITY_STRENGTH_BITS.
 * Albeit a full entropy assessment is provided for the noise source indicating
 * that it provides high entropy rates and considering that it deactivates
 * when it detects insufficient hardware, the chosen under estimation of
 * entropy is considered to be acceptable to all reviewers.
 */
static u32 jitterrng = LRNG_DRNG_SECURITY_STRENGTH_BITS>>4;
module_param(jitterrng, uint, 0644);
MODULE_PARM_DESC(jitterrng, "Entropy in bits of 256 data bits from Jitter RNG noise source");

/**
 * lrng_get_jent() - Get Jitter RNG entropy
 *
 * @outbuf: buffer to store entropy
 * @outbuflen: length of buffer
 *
 * Return:
 * * > 0 on success where value provides the added entropy in bits
 * * 0 if no fast source was available
 */
static struct rand_data *lrng_jent_state;

u32 lrng_get_jent(u8 *outbuf, unsigned int outbuflen)
{
	int ret;
	u32 ent_bits = jitterrng;
	unsigned long flags;
	static DEFINE_SPINLOCK(lrng_jent_lock);
	static int lrng_jent_initialized = 0;

	spin_lock_irqsave(&lrng_jent_lock, flags);

	if (!ent_bits || (lrng_jent_initialized == -1)) {
		spin_unlock_irqrestore(&lrng_jent_lock, flags);
		return 0;
	}

	if (!lrng_jent_initialized) {
		lrng_jent_state = jent_lrng_entropy_collector();
		if (!lrng_jent_state) {
			jitterrng = 0;
			lrng_jent_initialized = -1;
			spin_unlock_irqrestore(&lrng_jent_lock, flags);
			pr_info("Jitter RNG unusable on current system\n");
			return 0;
		}
		lrng_jent_initialized = 1;
		pr_debug("Jitter RNG working on current system\n");
	}
	ret = jent_read_entropy(lrng_jent_state, outbuf, outbuflen);
	spin_unlock_irqrestore(&lrng_jent_lock, flags);

	if (ret) {
		pr_debug("Jitter RNG failed with %d\n", ret);
		return 0;
	}

	/* Obtain entropy statement */
	if (outbuflen != LRNG_DRNG_SECURITY_STRENGTH_BYTES)
		ent_bits = (ent_bits * outbuflen<<3) /
			   LRNG_DRNG_SECURITY_STRENGTH_BITS;
	/* Cap entropy to buffer size in bits */
	ent_bits = min_t(u32, ent_bits, outbuflen<<3);
	pr_debug("obtained %u bits of entropy from Jitter RNG noise source\n",
		 ent_bits);

	return ent_bits;
}

u32 lrng_jent_entropylevel(void)
{
	return min_t(u32, jitterrng, LRNG_DRNG_SECURITY_STRENGTH_BITS);
}
