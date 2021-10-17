// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * LRNG auxiliary interfaces
 *
 * Copyright (C) 2019 - 2021 Stephan Mueller <smueller@chronox.de>
 * Copyright (C) 2017 Jason A. Donenfeld <Jason@zx2c4.com>. All
 * Rights Reserved.
 * Copyright (C) 2016 Jason Cooper <jason@lakedaemon.net>
 */

#include <linux/mm.h>
#include <linux/random.h>

#include "lrng_internal.h"

struct batched_entropy {
	union {
		u64 entropy_u64[LRNG_DRNG_BLOCKSIZE / sizeof(u64)];
		u32 entropy_u32[LRNG_DRNG_BLOCKSIZE / sizeof(u32)];
	};
	unsigned int position;
	spinlock_t batch_lock;
};

/*
 * Get a random word for internal kernel use only. The quality of the random
 * number is as good as /dev/urandom, but there is no backtrack protection,
 * with the goal of being quite fast and not depleting entropy.
 */
static DEFINE_PER_CPU(struct batched_entropy, batched_entropy_u64) = {
	.batch_lock	= __SPIN_LOCK_UNLOCKED(batched_entropy_u64.lock),
};

u64 get_random_u64(void)
{
	u64 ret;
	unsigned long flags;
	struct batched_entropy *batch;

	lrng_debug_report_seedlevel("get_random_u64");

	batch = raw_cpu_ptr(&batched_entropy_u64);
	spin_lock_irqsave(&batch->batch_lock, flags);
	if (batch->position % ARRAY_SIZE(batch->entropy_u64) == 0) {
		lrng_drng_get_atomic((u8 *)batch->entropy_u64,
				      LRNG_DRNG_BLOCKSIZE);
		batch->position = 0;
	}
	ret = batch->entropy_u64[batch->position++];
	spin_unlock_irqrestore(&batch->batch_lock, flags);
	return ret;
}
EXPORT_SYMBOL(get_random_u64);

static DEFINE_PER_CPU(struct batched_entropy, batched_entropy_u32) = {
	.batch_lock	= __SPIN_LOCK_UNLOCKED(batched_entropy_u32.lock),
};

u32 get_random_u32(void)
{
	u32 ret;
	unsigned long flags;
	struct batched_entropy *batch;

	lrng_debug_report_seedlevel("get_random_u32");

	batch = raw_cpu_ptr(&batched_entropy_u32);
	spin_lock_irqsave(&batch->batch_lock, flags);
	if (batch->position % ARRAY_SIZE(batch->entropy_u32) == 0) {
		lrng_drng_get_atomic((u8 *)batch->entropy_u32,
				      LRNG_DRNG_BLOCKSIZE);
		batch->position = 0;
	}
	ret = batch->entropy_u32[batch->position++];
	spin_unlock_irqrestore(&batch->batch_lock, flags);
	return ret;
}
EXPORT_SYMBOL(get_random_u32);

/*
 * It's important to invalidate all potential batched entropy that might
 * be stored before the crng is initialized, which we can do lazily by
 * simply resetting the counter to zero so that it's re-extracted on the
 * next usage.
 */
void invalidate_batched_entropy(void)
{
	int cpu;
	unsigned long flags;

	for_each_possible_cpu(cpu) {
		struct batched_entropy *batched_entropy;

		batched_entropy = per_cpu_ptr(&batched_entropy_u32, cpu);
		spin_lock_irqsave(&batched_entropy->batch_lock, flags);
		batched_entropy->position = 0;
		spin_unlock(&batched_entropy->batch_lock);

		batched_entropy = per_cpu_ptr(&batched_entropy_u64, cpu);
		spin_lock(&batched_entropy->batch_lock);
		batched_entropy->position = 0;
		spin_unlock_irqrestore(&batched_entropy->batch_lock, flags);
	}
}

/*
 * randomize_page - Generate a random, page aligned address
 * @start:	The smallest acceptable address the caller will take.
 * @range:	The size of the area, starting at @start, within which the
 *		random address must fall.
 *
 * If @start + @range would overflow, @range is capped.
 *
 * NOTE: Historical use of randomize_range, which this replaces, presumed that
 * @start was already page aligned.  We now align it regardless.
 *
 * Return: A page aligned address within [start, start + range).  On error,
 * @start is returned.
 */
unsigned long randomize_page(unsigned long start, unsigned long range)
{
	if (!PAGE_ALIGNED(start)) {
		range -= PAGE_ALIGN(start) - start;
		start = PAGE_ALIGN(start);
	}

	if (start > ULONG_MAX - range)
		range = ULONG_MAX - start;

	range >>= PAGE_SHIFT;

	if (range == 0)
		return start;

	return start + (get_random_long() % range << PAGE_SHIFT);
}
