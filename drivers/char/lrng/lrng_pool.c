// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * LRNG Entropy sources management
 * LRNG Slow Entropy Source: Auxiliary entropy pool
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

/*
 * This is the auxiliary pool
 *
 * The aux pool array is aligned to 8 bytes to comfort the kernel crypto API
 * cipher implementations of the hash functions used to read the pool: for some
 * accelerated implementations, we need an alignment to avoid a realignment
 * which involves memcpy(). The alignment to 8 bytes should satisfy all crypto
 * implementations.
 */
struct lrng_pool {
	u8 aux_pool[LRNG_POOL_SIZE];	/* Aux pool: digest state */
	atomic_t aux_entropy_bits;
	atomic_t digestsize;		/* Digest size of used hash */
	bool initialized;		/* Aux pool initialized? */

	/* Serialize read of entropy pool and update of aux pool */
	spinlock_t lock;
};

static struct lrng_pool lrng_pool __aligned(LRNG_KCAPI_ALIGN) = {
	.aux_entropy_bits	= ATOMIC_INIT(0),
	.digestsize		= ATOMIC_INIT(LRNG_ATOMIC_DIGEST_SIZE),
	.initialized		= false,
	.lock			= __SPIN_LOCK_UNLOCKED(lrng_pool.lock)
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

/* Entropy in bits present in aux pool */
u32 lrng_avail_aux_entropy(void)
{
	/* Cap available entropy with max entropy */
	u32 avail_bits = min_t(u32, lrng_get_digestsize(),
			       atomic_read_u32(&lrng_pool.aux_entropy_bits));

	/* Consider oversampling rate due to aux pool conditioning */
	return lrng_reduce_by_osr(avail_bits);
}

/* Set the digest size of the used hash in bytes */
static inline void lrng_set_digestsize(u32 digestsize)
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
	atomic_set(&lrng_pool.aux_entropy_bits, 0);
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
bool lrng_fully_seeded(struct entropy_buf *eb)
{
	return ((eb->a_bits + eb->b_bits + eb->c_bits + eb->d_bits) >=
		lrng_get_seed_entropy_osr());
}

/* Disable the fully seeded and operational mode */
void lrng_unset_operational(void)
{
	lrng_pool_all_numa_nodes_seeded(false);
	lrng_state.lrng_operational = false;
	lrng_state.lrng_fully_seeded = false;
}

/* Policy to enable LRNG operational mode */
static inline void lrng_set_operational(u32 external_es)
{
	if (lrng_state.lrng_fully_seeded &&
	    (lrng_sp80090b_startup_complete() ||
	     (lrng_get_seed_entropy_osr() <= external_es))) {
		lrng_state.lrng_operational = true;
		lrng_process_ready_list();
		lrng_init_wakeup();
		pr_info("LRNG fully operational\n");
	}
}

/* Set entropy content in user-space controllable aux pool */
void lrng_pool_set_entropy(u32 entropy_bits)
{
	atomic_set(&lrng_pool.aux_entropy_bits, entropy_bits);
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
	u32 requested_bits, seed_bits, external_es;

	if (state->lrng_operational)
		return;

	requested_bits = lrng_get_seed_entropy_osr();

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
	} else if (lrng_fully_seeded(eb)) {
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

/*
 * Replace old with new hash for auxiliary pool handling
 *
 * Assumption: the caller must guarantee that the new_cb is available during the
 * entire operation (e.g. it must hold the write lock against pointer updating).
 */
int lrng_aux_switch_hash(const struct lrng_crypto_cb *new_cb, void *new_hash,
			 const struct lrng_crypto_cb *old_cb)
{
	struct lrng_pool *pool = &lrng_pool;
	struct shash_desc *shash = (struct shash_desc *)pool->aux_pool;
	u8 digest[LRNG_MAX_DIGESTSIZE];
	int ret;

	if (!IS_ENABLED(CONFIG_LRNG_DRNG_SWITCH))
		return -EOPNOTSUPP;

	if (unlikely(!pool->initialized))
		return 0;

	/* Get the aux pool hash with old digest ... */
	ret = old_cb->lrng_hash_final(shash, digest) ?:
	      /* ... re-initialize the hash with the new digest ... */
	      new_cb->lrng_hash_init(shash, new_hash) ?:
	      /*
	       * ... feed the old hash into the new state. We may feed
	       * uninitialized memory into the new state, but this is
	       * considered no issue and even good as we have some more
	       * uncertainty here.
	       */
	      new_cb->lrng_hash_update(shash, digest, sizeof(digest));
	if (!ret) {
		lrng_set_digestsize(new_cb->lrng_hash_digestsize(new_hash));
		pr_debug("Re-initialize aux entropy pool with hash %s\n",
			 new_cb->lrng_hash_name());
	}

	memzero_explicit(digest, sizeof(digest));
	return ret;
}

/*
 * Insert data into auxiliary pool by hashing the input data together with
 * the auxiliary pool. The message digest is the new state of the auxiliary
 * pool.
 */
static int
lrng_pool_insert_aux_locked(const u8 *inbuf, u32 inbuflen, u32 entropy_bits)
{
	struct lrng_pool *pool = &lrng_pool;
	struct shash_desc *shash = (struct shash_desc *)pool->aux_pool;
	struct lrng_drng *drng = lrng_drng_init_instance();
	const struct lrng_crypto_cb *crypto_cb;
	unsigned long flags;
	void *hash;
	int ret;

	entropy_bits = min_t(u32, entropy_bits, inbuflen << 3);

	read_lock_irqsave(&drng->hash_lock, flags);

	crypto_cb = drng->crypto_cb;
	hash = drng->hash;

	if (unlikely(!pool->initialized)) {
		ret = crypto_cb->lrng_hash_init(shash, hash);
		if (ret)
			goto out;
		pool->initialized = true;
	}

	ret = crypto_cb->lrng_hash_update(shash, inbuf, inbuflen);
	if (ret)
		goto out;

	/*
	 * Cap the available entropy to the hash output size compliant to
	 * SP800-90B section 3.1.5.1 table 1.
	 */
	entropy_bits += atomic_read_u32(&pool->aux_entropy_bits);
	atomic_set(&pool->aux_entropy_bits,
		   min_t(u32, entropy_bits,
			 crypto_cb->lrng_hash_digestsize(hash) << 3));

out:
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

	lrng_pool_add_entropy();

	return ret;
}

/* Hot code path during boot - mix data into entropy pool during boot */
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

	/* Seed the DRNG with IRQ noise. */
	if (lrng_state.perform_seedwork)
		schedule_work(&lrng_state.lrng_seed_work);
	else
		lrng_drng_seed_work(NULL);
}

/************************* Get data from entropy pool *************************/

/**
 * Get auxiliary entropy pool and its entropy content for seed buffer.
 * Caller must hold lrng_pool.pool->lock.
 * @outbuf: buffer to store data in with size requested_bits
 * @requested_bits: Requested amount of entropy
 * @return: amount of entropy in outbuf in bits.
 */
static inline u32 lrng_get_aux_pool(u8 *outbuf, u32 requested_bits)
{
	struct lrng_pool *pool = &lrng_pool;
	struct shash_desc *shash = (struct shash_desc *)pool->aux_pool;
	struct lrng_drng *drng = lrng_drng_init_instance();
	const struct lrng_crypto_cb *crypto_cb;
	unsigned long flags;
	void *hash;
	u32 collected_ent_bits, returned_ent_bits, unused_bits = 0,
	    digestsize;
	u8 aux_output[LRNG_MAX_DIGESTSIZE];

	if (unlikely(!pool->initialized))
		return 0;

	read_lock_irqsave(&drng->hash_lock, flags);

	crypto_cb = drng->crypto_cb;
	hash = drng->hash;
	digestsize = crypto_cb->lrng_hash_digestsize(hash);

	/* Ensure that no more than the size of aux_pool can be requested */
	requested_bits = min_t(u32, requested_bits, (LRNG_MAX_DIGESTSIZE << 3));

	/* Cap entropy with entropy counter from aux pool and the used digest */
	collected_ent_bits = min_t(u32, digestsize << 3,
			       atomic_xchg_relaxed(&pool->aux_entropy_bits, 0));

	/* We collected too much entropy and put the overflow back */
	if (collected_ent_bits > (requested_bits + lrng_compress_osr())) {
		/* Amount of bits we collected too much */
		unused_bits = collected_ent_bits - requested_bits;
		/* Put entropy back */
		atomic_add(unused_bits, &pool->aux_entropy_bits);
		/* Fix collected entropy */
		collected_ent_bits = requested_bits;
	}

	/* Apply oversampling: discount requested oversampling rate */
	returned_ent_bits = lrng_reduce_by_osr(collected_ent_bits);

	pr_debug("obtained %u bits by collecting %u bits of entropy from aux pool, %u bits of entropy remaining\n",
		 returned_ent_bits, collected_ent_bits, unused_bits);

	/* Get the digest for the aux pool to be returned to the caller ... */
	if (crypto_cb->lrng_hash_final(shash, aux_output) ||
	    /*
	     * ... and re-initialize the aux state. Do not add the aux pool
	     * digest for backward secrecy as it will be added with the
	     * insertion of the complete seed buffer after it has been filled.
	     */
	    crypto_cb->lrng_hash_init(shash, hash)) {
		returned_ent_bits = 0;
	} else {
		/*
		 * Do not truncate the output size exactly to collected_ent_bits
		 * as the aux pool may contain data that is not credited with
		 * entropy, but we want to use them to stir the DRNG state.
		 */
		memcpy(outbuf, aux_output, requested_bits >> 3);
	}

	read_unlock_irqrestore(&drng->hash_lock, flags);
	memzero_explicit(aux_output, digestsize);
	return returned_ent_bits;
}

/* Fill the seed buffer with data from the noise sources */
void lrng_fill_seed_buffer(struct entropy_buf *entropy_buf, u32 requested_bits)
{
	struct lrng_pool *pool = &lrng_pool;
	struct lrng_state *state = &lrng_state;
	unsigned long flags;
	u32 pcpu_request, req_ent = lrng_sp80090c_compliant() ?
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

	/* Ensure aux pool extraction and backtracking op are atomic */
	spin_lock_irqsave(&pool->lock, flags);

	/* Concatenate the output of the entropy sources. */
	entropy_buf->a_bits = lrng_get_aux_pool(entropy_buf->a, requested_bits);

	/*
	 * If the aux pool returned entropy, pull respective less from per-CPU
	 * pool, but attempt to at least get LRNG_MIN_SEED_ENTROPY_BITS entropy.
	 */
	pcpu_request = max_t(u32, requested_bits - entropy_buf->a_bits,
			     LRNG_MIN_SEED_ENTROPY_BITS);
	entropy_buf->b_bits = lrng_pcpu_pool_hash(entropy_buf->b, pcpu_request,
						  state->lrng_fully_seeded);

	entropy_buf->c_bits = lrng_get_arch(entropy_buf->c, requested_bits);
	entropy_buf->d_bits = lrng_get_jent(entropy_buf->d, requested_bits);

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
