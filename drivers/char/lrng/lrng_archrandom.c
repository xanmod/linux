// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * LRNG Fast Entropy Source: CPU-based entropy source
 *
 * Copyright (C) 2016 - 2021, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

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
MODULE_PARM_DESC(archrandom, "Entropy in bits of 256 data bits from CPU noise source (e.g. RDRAND)");
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

/**
 * lrng_get_arch() - Get CPU noise source entropy
 *
 * @outbuf: buffer to store entropy of size LRNG_DRNG_SECURITY_STRENGTH_BYTES
 *
 * Return:
 * * > 0 on success where value provides the added entropy in bits
 * *   0 if no fast source was available
 */
u32 lrng_get_arch(u8 *outbuf, u32 requested_bits)
{
	u32 i, ent_bits = lrng_archrandom_entropylevel(requested_bits);

	/* operate on full blocks */
	BUILD_BUG_ON(LRNG_DRNG_SECURITY_STRENGTH_BYTES % sizeof(unsigned long));
	BUILD_BUG_ON(CONFIG_LRNG_SEED_BUFFER_INIT_ADD_BITS %
							 sizeof(unsigned long));
	/* ensure we have aligned buffers */
	BUILD_BUG_ON(LRNG_KCAPI_ALIGN % sizeof(unsigned long));

	if (!ent_bits)
		return 0;

	for (i = 0; i < (requested_bits >> 3);
	     i += sizeof(unsigned long)) {
		if (!arch_get_random_seed_long((unsigned long *)(outbuf + i)) &&
		    !arch_get_random_long((unsigned long *)(outbuf + i))) {
			archrandom = 0;
			return 0;
		}
	}

	pr_debug("obtained %u bits of entropy from CPU RNG noise source\n",
		 ent_bits);
	return ent_bits;
}
