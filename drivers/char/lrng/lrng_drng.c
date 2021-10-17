// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * LRNG DRNG processing
 *
 * Copyright (C) 2016 - 2021, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fips.h>
#include <linux/lrng.h>

#include "lrng_internal.h"

/*
 * Maximum number of seconds between DRNG reseed intervals of the DRNG. Note,
 * this is enforced with the next request of random numbers from the
 * DRNG. Setting this value to zero implies a reseeding attempt before every
 * generated random number.
 */
int lrng_drng_reseed_max_time = 600;

static atomic_t lrng_avail = ATOMIC_INIT(0);

DEFINE_MUTEX(lrng_crypto_cb_update);

/* DRNG for /dev/urandom, getrandom(2), get_random_bytes */
static struct lrng_drng lrng_drng_init = {
	.drng		= &chacha20,
	.crypto_cb	= &lrng_cc20_crypto_cb,
	.lock		= __MUTEX_INITIALIZER(lrng_drng_init.lock),
	.spin_lock	= __SPIN_LOCK_UNLOCKED(lrng_drng_init.spin_lock),
	.hash_lock	= __RW_LOCK_UNLOCKED(lrng_drng_init.hash_lock)
};

/*
 * DRNG for get_random_bytes when called in atomic context. This
 * DRNG will always use the ChaCha20 DRNG. It will never benefit from a
 * DRNG switch like the "regular" DRNG. If there was no DRNG switch, the atomic
 * DRNG is identical to the "regular" DRNG.
 *
 * The reason for having this is due to the fact that DRNGs other than
 * the ChaCha20 DRNG may sleep.
 */
static struct lrng_drng lrng_drng_atomic = {
	.drng		= &chacha20,
	.crypto_cb	= &lrng_cc20_crypto_cb,
	.spin_lock	= __SPIN_LOCK_UNLOCKED(lrng_drng_atomic.spin_lock),
	.hash_lock	= __RW_LOCK_UNLOCKED(lrng_drng_atomic.hash_lock)
};

static u32 max_wo_reseed = LRNG_DRNG_MAX_WITHOUT_RESEED;
#ifdef CONFIG_LRNG_RUNTIME_MAX_WO_RESEED_CONFIG
module_param(max_wo_reseed, uint, 0444);
MODULE_PARM_DESC(max_wo_reseed,
		 "Maximum number of DRNG generate operation without full reseed\n");
#endif

/********************************** Helper ************************************/

bool lrng_get_available(void)
{
	return likely(atomic_read(&lrng_avail));
}

void lrng_set_available(void)
{
	atomic_set(&lrng_avail, 1);
}

struct lrng_drng *lrng_drng_init_instance(void)
{
	return &lrng_drng_init;
}

struct lrng_drng *lrng_drng_atomic_instance(void)
{
	return &lrng_drng_atomic;
}

void lrng_drng_reset(struct lrng_drng *drng)
{
	atomic_set(&drng->requests, LRNG_DRNG_RESEED_THRESH);
	atomic_set(&drng->requests_since_fully_seeded, 0);
	drng->last_seeded = jiffies;
	drng->fully_seeded = false;
	drng->force_reseed = true;
	pr_debug("reset DRNG\n");
}

/* Initialize the default DRNG during boot */
static void lrng_drng_seed(struct lrng_drng *drng);
void lrng_drngs_init_cc20(bool force_seed)
{
	unsigned long flags = 0;

	if (lrng_get_available())
		return;

	lrng_drng_lock(&lrng_drng_init, &flags);
	if (lrng_get_available()) {
		lrng_drng_unlock(&lrng_drng_init, &flags);
		if (force_seed)
			goto seed;
		return;
	}

	lrng_drng_reset(&lrng_drng_init);
	lrng_cc20_init_state(&chacha20);
	lrng_drng_unlock(&lrng_drng_init, &flags);

	lrng_drng_lock(&lrng_drng_atomic, &flags);
	lrng_drng_reset(&lrng_drng_atomic);
	/*
	 * We do not initialize the state of the atomic DRNG as it is identical
	 * to the DRNG at this point.
	 */
	lrng_drng_unlock(&lrng_drng_atomic, &flags);

	lrng_set_available();

seed:
	/* Seed the DRNG with any entropy available */
	if (!lrng_pool_trylock()) {
		lrng_drng_seed(&lrng_drng_init);
		pr_info("ChaCha20 core initialized with first seeding\n");
		lrng_pool_unlock();
	} else {
		pr_info("ChaCha20 core initialized without seeding\n");
	}
}

bool lrng_sp80090c_compliant(void)
{
	if (!IS_ENABLED(CONFIG_LRNG_OVERSAMPLE_ENTROPY_SOURCES))
		return false;

	/* Entropy source hash must be capable of transporting enough entropy */
	if (lrng_get_digestsize() <
	    (lrng_security_strength() + CONFIG_LRNG_SEED_BUFFER_INIT_ADD_BITS))
		return false;

	/* SP800-90C only requested in FIPS mode */
	return fips_enabled;
}

/************************* Random Number Generation ***************************/

/* Inject a data buffer into the DRNG */
static void lrng_drng_inject(struct lrng_drng *drng,
			     const u8 *inbuf, u32 inbuflen, bool fully_seeded)
{
	const char *drng_type = unlikely(drng == &lrng_drng_atomic) ?
				"atomic" : "regular";
	unsigned long flags = 0;

	BUILD_BUG_ON(LRNG_DRNG_RESEED_THRESH > INT_MAX);
	pr_debug("seeding %s DRNG with %u bytes\n", drng_type, inbuflen);
	lrng_drng_lock(drng, &flags);
	if (drng->crypto_cb->lrng_drng_seed_helper(drng->drng,
						   inbuf, inbuflen) < 0) {
		pr_warn("seeding of %s DRNG failed\n", drng_type);
		drng->force_reseed = true;
	} else {
		int gc = LRNG_DRNG_RESEED_THRESH - atomic_read(&drng->requests);

		pr_debug("%s DRNG stats since last seeding: %lu secs; generate calls: %d\n",
			 drng_type,
			 (time_after(jiffies, drng->last_seeded) ?
			  (jiffies - drng->last_seeded) : 0) / HZ, gc);

		/* Count the numbers of generate ops since last fully seeded */
		if (fully_seeded)
			atomic_set(&drng->requests_since_fully_seeded, 0);
		else
			atomic_add(gc, &drng->requests_since_fully_seeded);

		drng->last_seeded = jiffies;
		atomic_set(&drng->requests, LRNG_DRNG_RESEED_THRESH);
		drng->force_reseed = false;

		if (!drng->fully_seeded) {
			drng->fully_seeded = fully_seeded;
			if (drng->fully_seeded)
				pr_debug("DRNG fully seeded\n");
		}

		if (drng->drng == lrng_drng_atomic.drng) {
			lrng_drng_atomic.last_seeded = jiffies;
			atomic_set(&lrng_drng_atomic.requests,
				   LRNG_DRNG_RESEED_THRESH);
			lrng_drng_atomic.force_reseed = false;
		}
	}
	lrng_drng_unlock(drng, &flags);
}

/*
 * Perform the seeding of the DRNG with data from noise source
 */
static inline void _lrng_drng_seed(struct lrng_drng *drng)
{
	struct entropy_buf seedbuf __aligned(LRNG_KCAPI_ALIGN);

	lrng_fill_seed_buffer(&seedbuf,
			      lrng_get_seed_entropy_osr(drng->fully_seeded));
	lrng_init_ops(&seedbuf);
	lrng_drng_inject(drng, (u8 *)&seedbuf, sizeof(seedbuf),
			 lrng_fully_seeded(drng->fully_seeded, &seedbuf));
	memzero_explicit(&seedbuf, sizeof(seedbuf));
}

static int lrng_drng_get(struct lrng_drng *drng, u8 *outbuf, u32 outbuflen);
static void lrng_drng_seed(struct lrng_drng *drng)
{
	_lrng_drng_seed(drng);

	BUILD_BUG_ON(LRNG_MIN_SEED_ENTROPY_BITS >
		     LRNG_DRNG_SECURITY_STRENGTH_BITS);

	/*
	 * Reseed atomic DRNG from current DRNG,
	 *
	 * We can obtain random numbers from DRNG as the lock type
	 * chosen by lrng_drng_get is usable with the current caller.
	 */
	if ((drng->drng != lrng_drng_atomic.drng) &&
	    (lrng_drng_atomic.force_reseed ||
	     atomic_read(&lrng_drng_atomic.requests) <= 0 ||
	     time_after(jiffies, lrng_drng_atomic.last_seeded +
			lrng_drng_reseed_max_time * HZ))) {
		u8 seedbuf[LRNG_DRNG_SECURITY_STRENGTH_BYTES]
						__aligned(LRNG_KCAPI_ALIGN);
		int ret = lrng_drng_get(drng, seedbuf, sizeof(seedbuf));

		if (ret < 0) {
			pr_warn("Error generating random numbers for atomic DRNG: %d\n",
				ret);
		} else {
			lrng_drng_inject(&lrng_drng_atomic, seedbuf, ret, true);
		}
		memzero_explicit(&seedbuf, sizeof(seedbuf));
	}
}

static inline void _lrng_drng_seed_work(struct lrng_drng *drng, u32 node)
{
	pr_debug("reseed triggered by interrupt noise source for DRNG on NUMA node %d\n",
		 node);
	lrng_drng_seed(drng);
	if (drng->fully_seeded) {
		/* Prevent reseed storm */
		drng->last_seeded += node * 100 * HZ;
		/* Prevent draining of pool on idle systems */
		lrng_drng_reseed_max_time += 100;
	}
}

/*
 * DRNG reseed trigger: Kernel thread handler triggered by the schedule_work()
 */
void lrng_drng_seed_work(struct work_struct *dummy)
{
	struct lrng_drng **lrng_drng = lrng_drng_instances();
	u32 node;

	if (lrng_drng) {
		for_each_online_node(node) {
			struct lrng_drng *drng = lrng_drng[node];

			if (drng && !drng->fully_seeded) {
				_lrng_drng_seed_work(drng, node);
				goto out;
			}
		}
	} else {
		if (!lrng_drng_init.fully_seeded) {
			_lrng_drng_seed_work(&lrng_drng_init, 0);
			goto out;
		}
	}

	lrng_pool_all_numa_nodes_seeded(true);

out:
	/* Allow the seeding operation to be called again */
	lrng_pool_unlock();
}

/* Force all DRNGs to reseed before next generation */
void lrng_drng_force_reseed(void)
{
	struct lrng_drng **lrng_drng = lrng_drng_instances();
	u32 node;

	/*
	 * If the initial DRNG is over the reseed threshold, allow a forced
	 * reseed only for the initial DRNG as this is the fallback for all. It
	 * must be kept seeded before all others to keep the LRNG operational.
	 */
	if (!lrng_drng ||
	    (atomic_read_u32(&lrng_drng_init.requests_since_fully_seeded) >
	     LRNG_DRNG_RESEED_THRESH)) {
		lrng_drng_init.force_reseed = lrng_drng_init.fully_seeded;
		pr_debug("force reseed of initial DRNG\n");
		return;
	}
	for_each_online_node(node) {
		struct lrng_drng *drng = lrng_drng[node];

		if (!drng)
			continue;

		drng->force_reseed = drng->fully_seeded;
		pr_debug("force reseed of DRNG on node %u\n", node);
	}
	lrng_drng_atomic.force_reseed = lrng_drng_atomic.fully_seeded;
}

/*
 * lrng_drng_get() - Get random data out of the DRNG which is reseeded
 * frequently.
 *
 * @outbuf: buffer for storing random data
 * @outbuflen: length of outbuf
 *
 * Return:
 * * < 0 in error case (DRNG generation or update failed)
 * * >=0 returning the returned number of bytes
 */
static int lrng_drng_get(struct lrng_drng *drng, u8 *outbuf, u32 outbuflen)
{
	unsigned long flags = 0;
	u32 processed = 0;

	if (!outbuf || !outbuflen)
		return 0;

	outbuflen = min_t(size_t, outbuflen, INT_MAX);

	lrng_drngs_init_cc20(false);

	/* If DRNG operated without proper reseed for too long, block LRNG */
	BUILD_BUG_ON(LRNG_DRNG_MAX_WITHOUT_RESEED < LRNG_DRNG_RESEED_THRESH);
	if (atomic_read_u32(&drng->requests_since_fully_seeded) > max_wo_reseed)
		lrng_unset_fully_seeded(drng);

	while (outbuflen) {
		u32 todo = min_t(u32, outbuflen, LRNG_DRNG_MAX_REQSIZE);
		int ret;

		/* All but the atomic DRNG are seeded during generation */
		if (atomic_dec_and_test(&drng->requests) ||
		    drng->force_reseed ||
		    time_after(jiffies, drng->last_seeded +
			       lrng_drng_reseed_max_time * HZ)) {
			if (likely(drng != &lrng_drng_atomic)) {
				if (lrng_pool_trylock()) {
					drng->force_reseed = true;
				} else {
					lrng_drng_seed(drng);
					lrng_pool_unlock();
				}
			}
		}

		lrng_drng_lock(drng, &flags);
		ret = drng->crypto_cb->lrng_drng_generate_helper(
					drng->drng, outbuf + processed, todo);
		lrng_drng_unlock(drng, &flags);
		if (ret <= 0) {
			pr_warn("getting random data from DRNG failed (%d)\n",
				ret);
			return -EFAULT;
		}
		processed += ret;
		outbuflen -= ret;
	}

	return processed;
}

int lrng_drng_get_atomic(u8 *outbuf, u32 outbuflen)
{
	return lrng_drng_get(&lrng_drng_atomic, outbuf, outbuflen);
}

int lrng_drng_get_sleep(u8 *outbuf, u32 outbuflen)
{
	struct lrng_drng **lrng_drng = lrng_drng_instances();
	struct lrng_drng *drng = &lrng_drng_init;
	int node = numa_node_id();

	might_sleep();

	if (lrng_drng && lrng_drng[node] && lrng_drng[node]->fully_seeded)
		drng = lrng_drng[node];

	return lrng_drng_get(drng, outbuf, outbuflen);
}

/* Reset LRNG such that all existing entropy is gone */
static void _lrng_reset(struct work_struct *work)
{
	struct lrng_drng **lrng_drng = lrng_drng_instances();
	unsigned long flags = 0;

	if (!lrng_drng) {
		lrng_drng_lock(&lrng_drng_init, &flags);
		lrng_drng_reset(&lrng_drng_init);
		lrng_drng_unlock(&lrng_drng_init, &flags);
	} else {
		u32 node;

		for_each_online_node(node) {
			struct lrng_drng *drng = lrng_drng[node];

			if (!drng)
				continue;
			lrng_drng_lock(drng, &flags);
			lrng_drng_reset(drng);
			lrng_drng_unlock(drng, &flags);
		}
	}
	lrng_set_entropy_thresh(LRNG_INIT_ENTROPY_BITS);

	lrng_reset_state();
}

static DECLARE_WORK(lrng_reset_work, _lrng_reset);

void lrng_reset(void)
{
	schedule_work(&lrng_reset_work);
}

/***************************** Initialize LRNG *******************************/

static int __init lrng_init(void)
{
	lrng_drngs_init_cc20(false);

	lrng_drngs_numa_alloc();
	return 0;
}

late_initcall(lrng_init);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("Linux Random Number Generator");
