// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * LRNG NUMA support
 *
 * Copyright (C) 2016 - 2021, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/lrng.h>
#include <linux/slab.h>

#include "lrng_internal.h"

static struct lrng_drng **lrng_drng __read_mostly = NULL;

struct lrng_drng **lrng_drng_instances(void)
{
	return smp_load_acquire(&lrng_drng);
}

/* Allocate the data structures for the per-NUMA node DRNGs */
static void _lrng_drngs_numa_alloc(struct work_struct *work)
{
	struct lrng_drng **drngs;
	struct lrng_drng *lrng_drng_init = lrng_drng_init_instance();
	u32 node;
	bool init_drng_used = false;

	mutex_lock(&lrng_crypto_cb_update);

	/* per-NUMA-node DRNGs are already present */
	if (lrng_drng)
		goto unlock;

	drngs = kcalloc(nr_node_ids, sizeof(void *), GFP_KERNEL|__GFP_NOFAIL);
	for_each_online_node(node) {
		struct lrng_drng *drng;

		if (!init_drng_used) {
			drngs[node] = lrng_drng_init;
			init_drng_used = true;
			continue;
		}

		drng = kmalloc_node(sizeof(struct lrng_drng),
				     GFP_KERNEL|__GFP_NOFAIL, node);
		memset(drng, 0, sizeof(lrng_drng));

		drng->crypto_cb = lrng_drng_init->crypto_cb;
		drng->drng = drng->crypto_cb->lrng_drng_alloc(
					LRNG_DRNG_SECURITY_STRENGTH_BYTES);
		if (IS_ERR(drng->drng)) {
			kfree(drng);
			goto err;
		}

		drng->hash = drng->crypto_cb->lrng_hash_alloc();
		if (IS_ERR(drng->hash)) {
			drng->crypto_cb->lrng_drng_dealloc(drng->drng);
			kfree(drng);
			goto err;
		}

		mutex_init(&drng->lock);
		spin_lock_init(&drng->spin_lock);
		rwlock_init(&drng->hash_lock);

		/*
		 * Switch the hash used by the per-CPU pool.
		 * We do not need to lock the new hash as it is not usable yet
		 * due to **drngs not yet being initialized.
		 */
		if (lrng_pcpu_switch_hash(node, drng->crypto_cb, drng->hash,
					  &lrng_cc20_crypto_cb))
			goto err;

		/*
		 * No reseeding of NUMA DRNGs from previous DRNGs as this
		 * would complicate the code. Let it simply reseed.
		 */
		lrng_drng_reset(drng);
		drngs[node] = drng;

		lrng_pool_inc_numa_node();
		pr_info("DRNG and entropy pool read hash for NUMA node %d allocated\n",
			node);
	}

	/* counterpart to smp_load_acquire in lrng_drng_instances */
	if (!cmpxchg_release(&lrng_drng, NULL, drngs)) {
		lrng_pool_all_numa_nodes_seeded(false);
		goto unlock;
	}

err:
	for_each_online_node(node) {
		struct lrng_drng *drng = drngs[node];

		if (drng == lrng_drng_init)
			continue;

		if (drng) {
			lrng_pcpu_switch_hash(node, &lrng_cc20_crypto_cb, NULL,
					      drng->crypto_cb);
			drng->crypto_cb->lrng_hash_dealloc(drng->hash);
			drng->crypto_cb->lrng_drng_dealloc(drng->drng);
			kfree(drng);
		}
	}
	kfree(drngs);

unlock:
	mutex_unlock(&lrng_crypto_cb_update);
}

static DECLARE_WORK(lrng_drngs_numa_alloc_work, _lrng_drngs_numa_alloc);

void lrng_drngs_numa_alloc(void)
{
	schedule_work(&lrng_drngs_numa_alloc_work);
}
