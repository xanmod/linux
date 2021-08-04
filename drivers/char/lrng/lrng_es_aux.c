// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * LRNG Slow Entropy Source: Auxiliary entropy pool
 *
 * Copyright (C) 2016 - 2021, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/lrng.h>

#include "lrng_internal.h"

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

/********************************** Helper ***********************************/

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

/* Set entropy content in user-space controllable aux pool */
void lrng_pool_set_entropy(u32 entropy_bits)
{
	atomic_set(&lrng_pool.aux_entropy_bits, entropy_bits);
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

/* Insert data into auxiliary pool by using the hash update function. */
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

void lrng_get_backtrack_aux(struct entropy_buf *entropy_buf, u32 requested_bits)
{
	struct lrng_pool *pool = &lrng_pool;
	unsigned long flags;

	/* Ensure aux pool extraction and backtracking op are atomic */
	spin_lock_irqsave(&pool->lock, flags);

	entropy_buf->a_bits = lrng_get_aux_pool(entropy_buf->a, requested_bits);

	/* Mix the extracted data back into pool for backtracking resistance */
	if (lrng_pool_insert_aux_locked((u8 *)entropy_buf,
					sizeof(struct entropy_buf), 0))
		pr_warn("Backtracking resistance operation failed\n");

	spin_unlock_irqrestore(&pool->lock, flags);
}
