// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * LRNG Fast Entropy Source: Jitter RNG
 *
 * Copyright (C) 2016 - 2021, Stephan Mueller <smueller@chronox.de>
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
static u32 jitterrng = CONFIG_LRNG_JENT_ENTROPY_RATE;
#ifdef CONFIG_LRNG_RUNTIME_ES_CONFIG
module_param(jitterrng, uint, 0644);
MODULE_PARM_DESC(jitterrng, "Entropy in bits of 256 data bits from Jitter RNG noise source");
#endif

static bool lrng_jent_initialized = false;
static struct rand_data *lrng_jent_state;

static int __init lrng_jent_initialize(void)
{
	/* Initialize the Jitter RNG after the clocksources are initialized. */
	if (jent_entropy_init() ||
	    (lrng_jent_state = jent_entropy_collector_alloc(1, 0)) == NULL) {
		jitterrng = 0;
		pr_info("Jitter RNG unusable on current system\n");
		return 0;
	}
	lrng_jent_initialized = true;
	lrng_pool_add_entropy();
	pr_debug("Jitter RNG working on current system\n");

	return 0;
}
device_initcall(lrng_jent_initialize);

/*
 * lrng_get_jent() - Get Jitter RNG entropy
 *
 * @outbuf: buffer to store entropy
 * @outbuflen: length of buffer
 *
 * Return:
 * * > 0 on success where value provides the added entropy in bits
 * * 0 if no fast source was available
 */
u32 lrng_get_jent(u8 *outbuf, u32 requested_bits)
{
	int ret;
	u32 ent_bits = lrng_jent_entropylevel(requested_bits);
	unsigned long flags;
	static DEFINE_SPINLOCK(lrng_jent_lock);

	spin_lock_irqsave(&lrng_jent_lock, flags);

	if (!lrng_jent_initialized) {
		spin_unlock_irqrestore(&lrng_jent_lock, flags);
		return 0;
	}

	ret = jent_read_entropy(lrng_jent_state, outbuf, requested_bits >> 3);
	spin_unlock_irqrestore(&lrng_jent_lock, flags);

	if (ret) {
		pr_debug("Jitter RNG failed with %d\n", ret);
		return 0;
	}

	pr_debug("obtained %u bits of entropy from Jitter RNG noise source\n",
		 ent_bits);

	return ent_bits;
}

u32 lrng_jent_entropylevel(u32 requested_bits)
{
	return lrng_fast_noise_entropylevel((lrng_jent_initialized) ?
					    jitterrng : 0, requested_bits);
}

void lrng_jent_es_state(unsigned char *buf, size_t buflen)
{
	snprintf(buf, buflen,
		 "JitterRNG ES properties:\n"
		 " Enabled: %s\n", lrng_jent_initialized ? "true" : "false");
}
