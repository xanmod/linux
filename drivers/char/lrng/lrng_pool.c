// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * LRNG Entropy pool management
 *
 * Copyright (C) 2016 - 2021, Stephan Mueller <smueller@chronox.de>
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

static u32 irq_entropy __read_mostly = LRNG_IRQ_ENTROPY_BITS;
module_param(irq_entropy, uint, 0444);
MODULE_PARM_DESC(irq_entropy,
		 "How many interrupts must be collected for obtaining 256 bits of entropy\n");

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
	struct lrng_pool *pool = &lrng_pool;
	u32 ent_bits = atomic_xchg_relaxed(&pool->aux_entropy_bits, 0),
	    old_digestsize = lrng_get_digestsize();

	atomic_set(&lrng_pool.digestsize, digestsize);

	/*
	 * In case the new digest is larger than the old one, cap the available
	 * entropy to the old message digest used to process the existing data.
	 */
	ent_bits = min_t(u32, ent_bits, old_digestsize);
	atomic_add(ent_bits, &pool->aux_entropy_bits);
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

/* Update the seeding threshold new entropy from external sources arrives */
void lrng_update_entropy_thresh(u32 new_entropy_bits)
{
	if (unlikely(!lrng_state_fully_seeded()) && new_entropy_bits) {
		/* if data arrive before fully seeded, lower trigger point */
		struct lrng_irq_info *irq_info = &lrng_pool.irq_info;
		u32 thresh = atomic_read_u32(&irq_info->num_events_thresh);
		u32 new_irqs = lrng_entropy_to_data(new_entropy_bits);

		thresh = new_irqs > thresh ? 0 : thresh - new_irqs;
		atomic_set(&irq_info->num_events_thresh, thresh);
	}
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
	/* Set a minimum number of interrupts that must be collected */
	irq_entropy = max_t(u32, LRNG_IRQ_ENTROPY_BITS, irq_entropy);

	if ((random_get_entropy() & LRNG_DATA_SLOTSIZE_MASK) ||
	    (random_get_entropy() & LRNG_DATA_SLOTSIZE_MASK)) {
		/*
		 * As the highres timer is identified here, previous interrupts
		 * obtained during boot time are treated like a lowres-timer
		 * would have been present.
		 */
		lrng_pool_configure(true, irq_entropy);
	} else {
		lrng_health_disable();
		lrng_pool_configure(false, irq_entropy *
					   LRNG_IRQ_OVERSAMPLING_FACTOR);
		pr_warn("operating without high-resolution timer and applying IRQ oversampling factor %u\n",
			LRNG_IRQ_OVERSAMPLING_FACTOR);
		lrng_pcpu_check_compression_state();
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
 * @eb: buffer containing the size of entropy currently injected into DRNG
 */
void lrng_init_ops(struct entropy_buf *eb)
{
	struct lrng_state *state = &lrng_state;
	u32 requested_bits, seed_bits, external_es, osr_bits;

	if (state->lrng_operational)
		return;

	requested_bits = lrng_security_strength();
	if (lrng_sp80090c_compliant())
		requested_bits = CONFIG_LRNG_SEED_BUFFER_INIT_ADD_BITS;

	/* Entropy provided by external entropy sources. */
	external_es = eb->a_bits + eb->c_bits + eb->d_bits;
	seed_bits = external_es + eb->b_bits;
	osr_bits = lrng_sp80090c_compliant() ?
					CONFIG_LRNG_OVERSAMPLE_ES_BITS : 0;

	/* DRNG is seeded with full security strength */
	if (state->lrng_fully_seeded) {
		state->lrng_operational = lrng_sp80090b_startup_complete();
		state->lrng_operational |= (requested_bits <= external_es);
		lrng_process_ready_list();
		lrng_init_wakeup();
	} else if (seed_bits >= requested_bits) {
		invalidate_batched_entropy();
		state->lrng_fully_seeded = true;
		state->lrng_operational = lrng_sp80090b_startup_complete();
		state->lrng_operational |= (requested_bits <= external_es);
		state->lrng_min_seeded = true;
		pr_info("LRNG fully seeded with %u bits of entropy\n",
			seed_bits);
		lrng_set_entropy_thresh(requested_bits + osr_bits);
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
					lrng_security_strength() + osr_bits));
			lrng_process_ready_list();
			lrng_init_wakeup();

		/* DRNG is seeded with at least LRNG_INIT_ENTROPY_BITS bits */
		} else if (seed_bits >= LRNG_INIT_ENTROPY_BITS) {
			pr_info("LRNG initial entropy level %u bits of entropy\n",
				seed_bits);
			lrng_set_entropy_thresh(
				lrng_slow_noise_req_entropy(
					LRNG_MIN_SEED_ENTROPY_BITS + osr_bits));
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

	lrng_drngs_init_cc20(true);
	invalidate_batched_entropy();

	return 0;
}

/*
 * Insert data into auxiliary pool by hashing the input data together with
 * the auxiliary pool. The message digest is the new state of the auxiliary
 * pool.
 */
static int
lrng_pool_insert_aux_locked(const u8 *inbuf, u32 inbuflen, u32 entropy_bits)
{
	SHASH_DESC_ON_STACK(shash, NULL);
	struct lrng_drng *drng = lrng_drng_init_instance();
	const struct lrng_crypto_cb *crypto_cb;
	struct lrng_pool *pool = &lrng_pool;
	unsigned long flags;
	void *hash;
	u32 digestsize;
	int ret;

	if (entropy_bits > (inbuflen << 3))
		entropy_bits = (inbuflen << 3);

	read_lock_irqsave(&drng->hash_lock, flags);

	crypto_cb = drng->crypto_cb;
	hash = drng->hash;
	digestsize = crypto_cb->lrng_hash_digestsize(hash);

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
	crypto_cb->lrng_hash_desc_zero(shash);
	read_unlock_irqrestore(&drng->hash_lock, flags);

	return ret;
}

int lrng_pool_insert_aux(const u8 *inbuf, u32 inbuflen, u32 entropy_bits)
{
	struct lrng_pool *pool = &lrng_pool;
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&pool->lock, flags);
	ret = lrng_pool_insert_aux_locked(inbuf, inbuflen, entropy_bits);
	spin_unlock_irqrestore(&pool->lock, flags);

	lrng_update_entropy_thresh(entropy_bits);

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

/**
 * Get auxiliary entropy pool and its entropy content for seed buffer.
 * @outbuf: buffer to store data in with size requested_bits
 * @requested_bits: Requested amount of entropy
 * @return: amount of entropy in outbuf in bits.
 */
static inline u32 lrng_get_aux_pool(u8 *outbuf, u32 requested_bits)
{
	struct lrng_pool *pool = &lrng_pool;
	u32 collected_ent_bits, returned_ent_bits, unused_bits = 0,
	    osr_bits = lrng_sp80090c_compliant() ?
					CONFIG_LRNG_OVERSAMPLE_ES_BITS : 0;

	/* Ensure that no more than the size of aux_pool can be requested */
	requested_bits = min_t(u32, requested_bits, (LRNG_MAX_DIGESTSIZE << 3));

	/* Cap entropy with entropy counter from aux pool and the used digest */
	collected_ent_bits = min_t(u32, lrng_get_digestsize(),
			       atomic_xchg_relaxed(&pool->aux_entropy_bits, 0));

	/* We collected too much entropy and put the overflow back */
	if (collected_ent_bits > (requested_bits + osr_bits)) {
		/* Amount of bits we collected too much */
		unused_bits = collected_ent_bits - requested_bits;
		/* Put entropy back */
		atomic_add(unused_bits, &pool->aux_entropy_bits);
		/* Fix collected entropy */
		collected_ent_bits = requested_bits;
	}

	/* Apply oversampling: discount requested oversampling rate */
	returned_ent_bits = (collected_ent_bits >= osr_bits) ?
					(collected_ent_bits - osr_bits) : 0;

	pr_debug("obtained %u bits by collecting %u bits of entropy from aux pool, %u bits of entropy remaining\n",
		 returned_ent_bits, collected_ent_bits, unused_bits);

	/*
	 * Do not truncate the output size exactly to collected_ent_bits as
	 * the aux pool may contain data that is not credited with entropy,
	 * but we want to use them to stir the DRNG state.
	 */
	memcpy(outbuf, pool->aux_pool, requested_bits >> 3);

	return returned_ent_bits;
}

/* Fill the seed buffer with data from the noise sources */
void lrng_fill_seed_buffer(struct entropy_buf *entropy_buf, u32 requested_bits)
{
	struct lrng_pool *pool = &lrng_pool;
	struct lrng_state *state = &lrng_state;
	unsigned long flags;
	u32 pcpu_request;

	/* Guarantee that requested bits is a multiple of bytes */
	BUILD_BUG_ON(LRNG_DRNG_SECURITY_STRENGTH_BITS % 8);

	/* Require at least 128 bits of entropy for any reseed. */
	if (state->lrng_fully_seeded &&
	    (lrng_avail_entropy() <
	     lrng_slow_noise_req_entropy(LRNG_MIN_SEED_ENTROPY_BITS)))
		goto wakeup;

	/* Ensure aux pool extraction and backtracking op are atomic */
	spin_lock_irqsave(&pool->lock, flags);

	/* Concatenate the output of the entropy sources. */
	entropy_buf->a_bits = lrng_get_aux_pool(entropy_buf->a, requested_bits);

	/*
	 * If the aux pool returned entropy, pull respective less from per-CPU
	 * pool, but attempt to at least get LRNG_MIN_SEED_ENTROPY_BITS entropy.
	 */
	pcpu_request = max_t(u32, requested_bits -
			     entropy_buf->a_bits, LRNG_MIN_SEED_ENTROPY_BITS);
	entropy_buf->b_bits = lrng_pcpu_pool_hash(entropy_buf->b, pcpu_request,
						  state->lrng_fully_seeded);

	entropy_buf->c_bits = lrng_get_arch(entropy_buf->c, requested_bits);
	entropy_buf->d_bits = lrng_get_jent(entropy_buf->d, requested_bits);

	/* also reseed the DRNG with the current time stamp */
	entropy_buf->now = random_get_entropy();

	/* Mix the extracted data back into pool for backtracking resistance */
	if (lrng_pool_insert_aux_locked((u8 *)entropy_buf,
					sizeof(struct entropy_buf), 0))
		pr_warn("Backtracking resistance operation failed\n");

	spin_unlock_irqrestore(&pool->lock, flags);

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
