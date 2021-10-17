// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * LRNG Entropy sources management
 *
 * Copyright (C) 2016 - 2021, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <asm/irq_regs.h>
#include <linux/percpu.h>
#include <linux/random.h>
#include <linux/utsname.h>
#include <linux/workqueue.h>

#include "lrng_internal.h"

struct lrng_state {
	bool can_invalidate;		/* Can invalidate batched entropy? */
	bool perform_seedwork;		/* Can seed work be performed? */
	bool lrng_operational;		/* Is DRNG operational? */
	bool lrng_fully_seeded;		/* Is DRNG fully seeded? */
	bool lrng_min_seeded;		/* Is DRNG minimally seeded? */
	bool all_online_numa_node_seeded;/* All NUMA DRNGs seeded? */

	/*
	 * To ensure that external entropy providers cannot dominate the
	 * internal noise sources but yet cannot be dominated by internal
	 * noise sources, the following booleans are intended to allow
	 * external to provide seed once when a DRNG reseed occurs. This
	 * triggering of external noise source is performed even when the
	 * entropy pool has sufficient entropy.
	 */
	bool lrng_seed_hw;		/* Allow HW to provide seed */
	bool lrng_seed_user;		/* Allow user space to provide seed */

	atomic_t boot_entropy_thresh;	/* Reseed threshold */
	atomic_t reseed_in_progress;	/* Flag for on executing reseed */
	struct work_struct lrng_seed_work;	/* (re)seed work queue */
};

static struct lrng_state lrng_state = {
	false, false, false, false, false, false, true, true,
	.boot_entropy_thresh	= ATOMIC_INIT(LRNG_INIT_ENTROPY_BITS),
	.reseed_in_progress	= ATOMIC_INIT(0),
};

/********************************** Helper ***********************************/

/* External entropy provider is allowed to provide seed data */
bool lrng_state_exseed_allow(enum lrng_external_noise_source source)
{
	if (source == lrng_noise_source_hw)
		return lrng_state.lrng_seed_hw;
	return lrng_state.lrng_seed_user;
}

/* Enable / disable external entropy provider to furnish seed */
void lrng_state_exseed_set(enum lrng_external_noise_source source, bool type)
{
	if (source == lrng_noise_source_hw)
		lrng_state.lrng_seed_hw = type;
	else
		lrng_state.lrng_seed_user = type;
}

static inline void lrng_state_exseed_allow_all(void)
{
	lrng_state_exseed_set(lrng_noise_source_hw, true);
	lrng_state_exseed_set(lrng_noise_source_user, true);
}

/*
 * Reading of the LRNG pool is only allowed by one caller. The reading is
 * only performed to (re)seed DRNGs. Thus, if this "lock" is already taken,
 * the reseeding operation is in progress. The caller is not intended to wait
 * but continue with its other operation.
 */
int lrng_pool_trylock(void)
{
	return atomic_cmpxchg(&lrng_state.reseed_in_progress, 0, 1);
}

void lrng_pool_unlock(void)
{
	atomic_set(&lrng_state.reseed_in_progress, 0);
}

/* Set new entropy threshold for reseeding during boot */
void lrng_set_entropy_thresh(u32 new_entropy_bits)
{
	atomic_set(&lrng_state.boot_entropy_thresh, new_entropy_bits);
}

/*
 * Reset LRNG state - the entropy counters are reset, but the data that may
 * or may not have entropy remains in the pools as this data will not hurt.
 */
void lrng_reset_state(void)
{
	lrng_pool_set_entropy(0);
	lrng_pcpu_reset();
	lrng_state.lrng_operational = false;
	lrng_state.lrng_fully_seeded = false;
	lrng_state.lrng_min_seeded = false;
	lrng_state.all_online_numa_node_seeded = false;
	pr_debug("reset LRNG\n");
}

/* Set flag that all DRNGs are fully seeded */
void lrng_pool_all_numa_nodes_seeded(bool set)
{
	lrng_state.all_online_numa_node_seeded = set;
}

/* Return boolean whether LRNG reached minimally seed level */
bool lrng_state_min_seeded(void)
{
	return lrng_state.lrng_min_seeded;
}

/* Return boolean whether LRNG reached fully seed level */
bool lrng_state_fully_seeded(void)
{
	return lrng_state.lrng_fully_seeded;
}

/* Return boolean whether LRNG is considered fully operational */
bool lrng_state_operational(void)
{
	return lrng_state.lrng_operational;
}

/* Policy to check whether entropy buffer contains full seeded entropy */
bool lrng_fully_seeded(bool fully_seeded, struct entropy_buf *eb)
{
	return ((eb->a_bits + eb->b_bits + eb->c_bits + eb->d_bits) >=
		lrng_get_seed_entropy_osr(fully_seeded));
}

/* Mark one DRNG as not fully seeded */
void lrng_unset_fully_seeded(struct lrng_drng *drng)
{
	drng->fully_seeded = false;
	lrng_pool_all_numa_nodes_seeded(false);

	/*
	 * The init DRNG instance must always be fully seeded as this instance
	 * is the fall-back if any of the per-NUMA node DRNG instances is
	 * insufficiently seeded. Thus, we mark the entire LRNG as
	 * non-operational if the initial DRNG becomes not fully seeded.
	 */
	if (drng == lrng_drng_init_instance() && lrng_state_operational()) {
		pr_debug("LRNG set to non-operational\n");
		lrng_state.lrng_operational = false;
		lrng_state.lrng_fully_seeded = false;

		/* If sufficient entropy is available, reseed now. */
		lrng_pool_add_entropy();
	}
}

/* Policy to enable LRNG operational mode */
static inline void lrng_set_operational(u32 external_es)
{
	/* LRNG is operational if the initial DRNG is fully seeded ... */
	if (lrng_state.lrng_fully_seeded &&
	    /* ... and either internal ES SP800-90B startup is complete ... */
	    (lrng_sp80090b_startup_complete() ||
	    /* ... or the external ES provided sufficient entropy. */
	     (lrng_get_seed_entropy_osr(lrng_state_fully_seeded()) <=
	      external_es))) {
		lrng_state.lrng_operational = true;
		lrng_process_ready_list();
		lrng_init_wakeup();
		pr_info("LRNG fully operational\n");
	}
}

/* Available entropy in the entire LRNG considering all entropy sources */
u32 lrng_avail_entropy(void)
{
	u32 ent_thresh = lrng_security_strength();

	/*
	 * Apply oversampling during initialization according to SP800-90C as
	 * we request a larger buffer from the ES.
	 */
	if (lrng_sp80090c_compliant() &&
	    !lrng_state.all_online_numa_node_seeded)
		ent_thresh += CONFIG_LRNG_SEED_BUFFER_INIT_ADD_BITS;

	return lrng_pcpu_avail_entropy() + lrng_avail_aux_entropy() +
	       lrng_archrandom_entropylevel(ent_thresh) +
	       lrng_jent_entropylevel(ent_thresh);
}

/*
 * lrng_init_ops() - Set seed stages of LRNG
 *
 * Set the slow noise source reseed trigger threshold. The initial threshold
 * is set to the minimum data size that can be read from the pool: a word. Upon
 * reaching this value, the next seed threshold of 128 bits is set followed
 * by 256 bits.
 *
 * @eb: buffer containing the size of entropy currently injected into DRNG
 */
void lrng_init_ops(struct entropy_buf *eb)
{
	struct lrng_state *state = &lrng_state;
	u32 requested_bits, seed_bits, external_es;

	if (state->lrng_operational)
		return;

	requested_bits = lrng_get_seed_entropy_osr(
					state->all_online_numa_node_seeded);

	/*
	 * Entropy provided by external entropy sources - if they provide
	 * the requested amount of entropy, unblock the interface.
	 */
	external_es = eb->a_bits + eb->c_bits + eb->d_bits;
	seed_bits = external_es + eb->b_bits;

	/* DRNG is seeded with full security strength */
	if (state->lrng_fully_seeded) {
		lrng_set_operational(external_es);
		lrng_set_entropy_thresh(requested_bits);
	} else if (lrng_fully_seeded(state->all_online_numa_node_seeded, eb)) {
		if (state->can_invalidate)
			invalidate_batched_entropy();

		state->lrng_fully_seeded = true;
		lrng_set_operational(external_es);
		state->lrng_min_seeded = true;
		pr_info("LRNG fully seeded with %u bits of entropy\n",
			seed_bits);
		lrng_set_entropy_thresh(requested_bits);
	} else if (!state->lrng_min_seeded) {

		/* DRNG is seeded with at least 128 bits of entropy */
		if (seed_bits >= LRNG_MIN_SEED_ENTROPY_BITS) {
			if (state->can_invalidate)
				invalidate_batched_entropy();

			state->lrng_min_seeded = true;
			pr_info("LRNG minimally seeded with %u bits of entropy\n",
				seed_bits);
			lrng_set_entropy_thresh(requested_bits);
			lrng_init_wakeup();

		/* DRNG is seeded with at least LRNG_INIT_ENTROPY_BITS bits */
		} else if (seed_bits >= LRNG_INIT_ENTROPY_BITS) {
			pr_info("LRNG initial entropy level %u bits of entropy\n",
				seed_bits);
			lrng_set_entropy_thresh(LRNG_MIN_SEED_ENTROPY_BITS);
		}
	}
}

int __init rand_initialize(void)
{
	struct seed {
		ktime_t time;
		unsigned long data[(LRNG_MAX_DIGESTSIZE /
				    sizeof(unsigned long))];
		struct new_utsname utsname;
	} seed __aligned(LRNG_KCAPI_ALIGN);
	unsigned int i;

	BUILD_BUG_ON(LRNG_MAX_DIGESTSIZE % sizeof(unsigned long));

	seed.time = ktime_get_real();

	for (i = 0; i < ARRAY_SIZE(seed.data); i++) {
		if (!arch_get_random_seed_long_early(&(seed.data[i])) &&
		    !arch_get_random_long_early(&seed.data[i]))
			seed.data[i] = random_get_entropy();
	}
	memcpy(&seed.utsname, utsname(), sizeof(*(utsname())));

	lrng_pool_insert_aux((u8 *)&seed, sizeof(seed), 0);
	memzero_explicit(&seed, sizeof(seed));

	/* Initialize the seed work queue */
	INIT_WORK(&lrng_state.lrng_seed_work, lrng_drng_seed_work);
	lrng_state.perform_seedwork = true;

	lrng_drngs_init_cc20(true);
	invalidate_batched_entropy();

	lrng_state.can_invalidate = true;

	return 0;
}

/* Interface requesting a reseed of the DRNG */
void lrng_pool_add_entropy(void)
{
	/*
	 * Once all DRNGs are fully seeded, the interrupt noise
	 * sources will not trigger any reseeding any more.
	 */
	if (likely(lrng_state.all_online_numa_node_seeded))
		return;

	/* Only try to reseed if the DRNG is alive. */
	if (!lrng_get_available())
		return;

	/* Only trigger the DRNG reseed if we have collected entropy. */
	if (lrng_avail_entropy() <
	    atomic_read_u32(&lrng_state.boot_entropy_thresh))
		return;

	/* Ensure that the seeding only occurs once at any given time. */
	if (lrng_pool_trylock())
		return;

	/* Seed the DRNG with any available noise. */
	if (lrng_state.perform_seedwork)
		schedule_work(&lrng_state.lrng_seed_work);
	else
		lrng_drng_seed_work(NULL);
}

/* Fill the seed buffer with data from the noise sources */
void lrng_fill_seed_buffer(struct entropy_buf *entropy_buf, u32 requested_bits)
{
	struct lrng_state *state = &lrng_state;
	u32 req_ent = lrng_sp80090c_compliant() ?
			  lrng_security_strength() : LRNG_MIN_SEED_ENTROPY_BITS;

	/* Guarantee that requested bits is a multiple of bytes */
	BUILD_BUG_ON(LRNG_DRNG_SECURITY_STRENGTH_BITS % 8);

	/* always reseed the DRNG with the current time stamp */
	entropy_buf->now = random_get_entropy();

	/*
	 * Require at least 128 bits of entropy for any reseed. If the LRNG is
	 * operated SP800-90C compliant we want to comply with SP800-90A section
	 * 9.2 mandating that DRNG is reseeded with the security strength.
	 */
	if (state->lrng_fully_seeded && (lrng_avail_entropy() < req_ent)) {
		entropy_buf->a_bits = entropy_buf->b_bits = 0;
		entropy_buf->c_bits = entropy_buf->d_bits = 0;
		goto wakeup;
	}

	/* Concatenate the output of the entropy sources. */
	entropy_buf->b_bits = lrng_pcpu_pool_hash(entropy_buf->b,
						  requested_bits,
						  state->lrng_fully_seeded);
	entropy_buf->c_bits = lrng_get_arch(entropy_buf->c, requested_bits);
	entropy_buf->d_bits = lrng_get_jent(entropy_buf->d, requested_bits);
	lrng_get_backtrack_aux(entropy_buf, requested_bits);

	/* allow external entropy provider to provide seed */
	lrng_state_exseed_allow_all();

wakeup:
	/*
	 * Shall we wake up user space writers? This location covers
	 * ensures that the user space provider does not dominate the internal
	 * noise sources since in case the first call of this function finds
	 * sufficient entropy in the entropy pool, it will not trigger the
	 * wakeup. This implies that when the next /dev/urandom read happens,
	 * the entropy pool is drained.
	 */
	lrng_writer_wakeup();
}
