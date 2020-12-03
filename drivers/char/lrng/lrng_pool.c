// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * LRNG Entropy pool management
 *
 * Copyright (C) 2016 - 2020, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <asm/irq_regs.h>
#include <linux/lrng.h>
#include <linux/percpu.h>
#include <linux/random.h>
#include <linux/utsname.h>
#include <linux/workqueue.h>

#include "lrng_internal.h"
#include "lrng_sw_noise.h"

struct lrng_state {
	bool lrng_operational;		/* Is DRNG operational? */
	bool lrng_fully_seeded;		/* Is DRNG fully seeded? */
	bool lrng_min_seeded;		/* Is DRNG minimally seeded? */

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

	struct work_struct lrng_seed_work;	/* (re)seed work queue */
};

static struct lrng_pool lrng_pool __aligned(LRNG_KCAPI_ALIGN) = {
	.aux_entropy_bits	= ATOMIC_INIT(0),
	.digestsize		= ATOMIC_INIT(LRNG_ATOMIC_DIGEST_SIZE),
	.irq_info		= {
		.irq_entropy_bits	= LRNG_IRQ_ENTROPY_BITS,
		.num_events_thresh	= ATOMIC_INIT(LRNG_INIT_ENTROPY_BITS),
		/* Sample IRQ pointer data at least during boot */
		.irq_highres_timer	= false },
	.lock			= __SPIN_LOCK_UNLOCKED(lrng_pool.lock)
};

static struct lrng_state lrng_state = { false, false, false, true, true };

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

/* Initialize the seed work queue */
void lrng_state_init_seed_work(void)
{
	INIT_WORK(&lrng_state.lrng_seed_work, lrng_drng_seed_work);
}

/* Convert entropy in bits into number of IRQs with the same entropy content. */
u32 lrng_entropy_to_data(u32 entropy_bits)
{
	return ((entropy_bits * lrng_pool.irq_info.irq_entropy_bits) /
		LRNG_DRNG_SECURITY_STRENGTH_BITS);
}

/* Convert number of IRQs into entropy value. */
u32 lrng_data_to_entropy(u32 irqnum)
{
	return ((irqnum * LRNG_DRNG_SECURITY_STRENGTH_BITS) /
		lrng_pool.irq_info.irq_entropy_bits);
}

/* Entropy in bits present in aux pool */
u32 lrng_avail_aux_entropy(void)
{
	/* Cap available entropy with max entropy */
	return min_t(u32, atomic_read_u32(&lrng_pool.digestsize) << 3,
		     atomic_read_u32(&lrng_pool.aux_entropy_bits));
}

/* Set the digest size of the used hash in bytes */
void lrng_set_digestsize(u32 digestsize)
{
	atomic_set(&lrng_pool.digestsize, digestsize);
}

/* Obtain the digest size provided by the used hash in bits */
u32 lrng_get_digestsize(void)
{
	return atomic_read_u32(&lrng_pool.digestsize) << 3;
}

/* Set new entropy threshold for reseeding during boot */
void lrng_set_entropy_thresh(u32 new_entropy_bits)
{
	atomic_set(&lrng_pool.irq_info.num_events_thresh,
		   lrng_entropy_to_data(new_entropy_bits));
}

/*
 * Reading of the LRNG pool is only allowed by one caller. The reading is
 * only performed to (re)seed DRNGs. Thus, if this "lock" is already taken,
 * the reseeding operation is in progress. The caller is not intended to wait
 * but continue with its other operation.
 */
int lrng_pool_trylock(void)
{
	return atomic_cmpxchg(&lrng_pool.irq_info.reseed_in_progress, 0, 1);
}

void lrng_pool_unlock(void)
{
	atomic_set(&lrng_pool.irq_info.reseed_in_progress, 0);
}

/*
 * Reset LRNG state - the entropy counters are reset, but the data that may
 * or may not have entropy remains in the pools as this data will not hurt.
 */
void lrng_reset_state(void)
{
	atomic_set(&lrng_pool.aux_entropy_bits, 0);
	lrng_pcpu_reset();
	lrng_state.lrng_operational = false;
	lrng_state.lrng_fully_seeded = false;
	lrng_state.lrng_min_seeded = false;
	lrng_pool.all_online_numa_node_seeded = false;
	pr_debug("reset LRNG\n");
}

/* Set flag that all DRNGs are fully seeded */
void lrng_pool_all_numa_nodes_seeded(void)
{
	lrng_pool.all_online_numa_node_seeded = true;
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

/* Return boolean whether LRNG identified presence of high-resolution timer */
bool lrng_pool_highres_timer(void)
{
	return lrng_pool.irq_info.irq_highres_timer;
}

/* Set entropy content in user-space controllable aux pool */
void lrng_pool_set_entropy(u32 entropy_bits)
{
	atomic_set(&lrng_pool.aux_entropy_bits, entropy_bits);
}

static void lrng_pool_configure(bool highres_timer, u32 irq_entropy_bits)
{
	struct lrng_irq_info *irq_info = &lrng_pool.irq_info;

	irq_info->irq_highres_timer = highres_timer;
	if (irq_info->irq_entropy_bits != irq_entropy_bits) {
		irq_info->irq_entropy_bits = irq_entropy_bits;
		/* Reset the threshold based on new oversampling factor. */
		lrng_set_entropy_thresh(atomic_read_u32(
						&irq_info->num_events_thresh));
	}
}

static int __init lrng_init_time_source(void)
{
	if ((random_get_entropy() & LRNG_DATA_SLOTSIZE_MASK) ||
	    (random_get_entropy() & LRNG_DATA_SLOTSIZE_MASK)) {
		/*
		 * As the highres timer is identified here, previous interrupts
		 * obtained during boot time are treated like a lowres-timer
		 * would have been present.
		 */
		lrng_pool_configure(true, LRNG_IRQ_ENTROPY_BITS);
	} else {
		lrng_health_disable();
		lrng_pool_configure(false, LRNG_IRQ_ENTROPY_BITS *
					   LRNG_IRQ_OVERSAMPLING_FACTOR);
		pr_warn("operating without high-resolution timer and applying IRQ oversampling factor %u\n",
			LRNG_IRQ_OVERSAMPLING_FACTOR);
	}

	return 0;
}

core_initcall(lrng_init_time_source);

/**
 * lrng_init_ops() - Set seed stages of LRNG
 *
 * Set the slow noise source reseed trigger threshold. The initial threshold
 * is set to the minimum data size that can be read from the pool: a word. Upon
 * reaching this value, the next seed threshold of 128 bits is set followed
 * by 256 bits.
 *
 * @entropy_bits: size of entropy currently injected into DRNG
 */
void lrng_init_ops(u32 seed_bits)
{
	struct lrng_state *state = &lrng_state;

	if (state->lrng_operational)
		return;

	/* DRNG is seeded with full security strength */
	if (state->lrng_fully_seeded) {
		state->lrng_operational = lrng_sp80090b_startup_complete();
		lrng_process_ready_list();
		lrng_init_wakeup();
	} else if (seed_bits >= lrng_security_strength()) {
		invalidate_batched_entropy();
		state->lrng_fully_seeded = true;
		state->lrng_operational = lrng_sp80090b_startup_complete();
		state->lrng_min_seeded = true;
		pr_info("LRNG fully seeded with %u bits of entropy\n",
			seed_bits);
		lrng_set_entropy_thresh(lrng_security_strength());
		lrng_process_ready_list();
		lrng_init_wakeup();

	} else if (!state->lrng_min_seeded) {

		/* DRNG is seeded with at least 128 bits of entropy */
		if (seed_bits >= LRNG_MIN_SEED_ENTROPY_BITS) {
			invalidate_batched_entropy();
			state->lrng_min_seeded = true;
			pr_info("LRNG minimally seeded with %u bits of entropy\n",
				seed_bits);
			lrng_set_entropy_thresh(
				lrng_slow_noise_req_entropy(
						lrng_security_strength()));
			lrng_process_ready_list();
			lrng_init_wakeup();

		/* DRNG is seeded with at least LRNG_INIT_ENTROPY_BITS bits */
		} else if (seed_bits >= LRNG_INIT_ENTROPY_BITS) {
			pr_info("LRNG initial entropy level %u bits of entropy\n",
				seed_bits);
			lrng_set_entropy_thresh(
				lrng_slow_noise_req_entropy(
					LRNG_MIN_SEED_ENTROPY_BITS));
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

	lrng_drng_init_early();

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

	return 0;
}

/*
 * Insert data into auxiliary pool by hashing the input data together with
 * the auxiliary pool. The message digest is the new state of the auxiliary
 * pool.
 */
int lrng_pool_insert_aux(const u8 *inbuf, u32 inbuflen, u32 entropy_bits)
{
	SHASH_DESC_ON_STACK(shash, NULL);
	struct lrng_drng *drng = lrng_drng_init_instance();
	const struct lrng_crypto_cb *crypto_cb;
	struct lrng_pool *pool = &lrng_pool;
	unsigned long flags, flags2;
	void *hash;
	u32 digestsize;
	int ret;

	if (entropy_bits > (inbuflen << 3))
		entropy_bits = (inbuflen << 3);

	read_lock_irqsave(&drng->hash_lock, flags);

	crypto_cb = drng->crypto_cb;
	hash = drng->hash;
	digestsize = crypto_cb->lrng_hash_digestsize(hash);

	spin_lock_irqsave(&pool->lock, flags2);
	ret = crypto_cb->lrng_hash_init(shash, hash) ?:
	      /* Hash auxiliary pool ... */
	      crypto_cb->lrng_hash_update(shash, pool->aux_pool, digestsize) ?:
	      /* ... together with input data ... */
	      crypto_cb->lrng_hash_update(shash, inbuf, inbuflen) ?:
	      /* ... to form mew auxiliary pool state. */
	      crypto_cb->lrng_hash_final(shash, pool->aux_pool);
	if (ret)
		goto out;

	/*
	 * Cap the available entropy to the hash output size compliant to
	 * SP800-90B section 3.1.5.1 table 1.
	 */
	entropy_bits += atomic_read_u32(&pool->aux_entropy_bits);
	if (entropy_bits > digestsize << 3)
		entropy_bits = digestsize << 3;
	atomic_set(&pool->aux_entropy_bits, entropy_bits);

out:
	spin_unlock_irqrestore(&pool->lock, flags2);
	read_unlock_irqrestore(&drng->hash_lock, flags);

	return ret;
}

/* Hot code path during boot - mix data into entropy pool during boot */
void lrng_pool_add_irq(void)
{
	/*
	 * Once all DRNGs are fully seeded, the interrupt noise
	 * sources will not trigger any reseeding any more.
	 */
	if (likely(lrng_pool.all_online_numa_node_seeded))
		return;

	/* Only try to reseed if the DRNG is alive. */
	if (!lrng_get_available())
		return;

	/* Only trigger the DRNG reseed if we have collected enough IRQs. */
	if (lrng_pcpu_avail_irqs() <
	    atomic_read_u32(&lrng_pool.irq_info.num_events_thresh))
		return;

	/* Ensure that the seeding only occurs once at any given time. */
	if (lrng_pool_trylock())
		return;

	/* Seed the DRNG with IRQ noise. */
	schedule_work(&lrng_state.lrng_seed_work);
}

/************************* Get data from entropy pool *************************/

static inline u32 lrng_get_pool(u8 *outbuf, u32 requested_entropy_bits)
{
	struct lrng_state *state = &lrng_state;

	return lrng_pcpu_pool_hash(&lrng_pool, outbuf, requested_entropy_bits,
				   state->lrng_fully_seeded);
}

/* Fill the seed buffer with data from the noise sources */
int lrng_fill_seed_buffer(struct entropy_buf *entropy_buf)
{
	struct lrng_state *state = &lrng_state;
	u32 total_entropy_bits = 0;

	/* Guarantee that requested bits is a multiple of bytes */
	BUILD_BUG_ON(LRNG_DRNG_SECURITY_STRENGTH_BITS % 8);

	/* Require at least 128 bits of entropy for any reseed. */
	if (state->lrng_fully_seeded &&
	    (lrng_avail_entropy() <
	     lrng_slow_noise_req_entropy(LRNG_MIN_SEED_ENTROPY_BITS)))
		goto wakeup;

	/*
	 * Concatenate the output of the noise sources. This would be the
	 * spot to add an entropy extractor logic if desired. Note, this
	 * has the ability to collect entropy equal or larger than the DRNG
	 * strength.
	 */
	total_entropy_bits = lrng_get_pool(entropy_buf->a,
					   LRNG_DRNG_SECURITY_STRENGTH_BITS);
	total_entropy_bits += lrng_get_arch(entropy_buf->b);
	total_entropy_bits += lrng_get_jent(entropy_buf->c,
					    LRNG_DRNG_SECURITY_STRENGTH_BYTES);

	/* also reseed the DRNG with the current time stamp */
	entropy_buf->now = random_get_entropy();

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

	return total_entropy_bits;
}
