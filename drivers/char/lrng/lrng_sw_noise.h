/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * LRNG Slow Noise Source: Time stamp array handling
 *
 * Copyright (C) 2016 - 2020, Stephan Mueller <smueller@chronox.de>
 */

/*
 * To limit the impact on the interrupt handling, the LRNG concatenates
 * entropic LSB parts of the time stamps in a per-CPU array and only
 * injects them into the entropy pool when the array is full.
 */

/* Store multiple integers in one u32 */
#define LRNG_DATA_SLOTSIZE_BITS		(8)
#define LRNG_DATA_SLOTSIZE_MASK		((1 << LRNG_DATA_SLOTSIZE_BITS) - 1)
#define LRNG_DATA_ARRAY_MEMBER_BITS	(4 << 3) /* ((sizeof(u32)) << 3) */
#define LRNG_DATA_SLOTS_PER_UINT	(LRNG_DATA_ARRAY_MEMBER_BITS / \
					 LRNG_DATA_SLOTSIZE_BITS)

/*
 * Number of time values to store in the array - in small environments
 * only one atomic_t variable per CPU is used.
 */
#define LRNG_DATA_NUM_VALUES		(CONFIG_LRNG_COLLECTION_SIZE)
/* Mask of LSB of time stamp to store */
#define LRNG_DATA_WORD_MASK		(LRNG_DATA_NUM_VALUES - 1)

#define LRNG_DATA_SLOTS_MASK		(LRNG_DATA_SLOTS_PER_UINT - 1)
#define LRNG_DATA_ARRAY_SIZE		(LRNG_DATA_NUM_VALUES /	\
					 LRNG_DATA_SLOTS_PER_UINT)

/* Starting bit index of slot */
static inline unsigned int lrng_data_slot2bitindex(unsigned int slot)
{
	return (LRNG_DATA_SLOTSIZE_BITS * slot);
}

/* Convert index into the array index */
static inline unsigned int lrng_data_idx2array(unsigned int idx)
{
	return idx / LRNG_DATA_SLOTS_PER_UINT;
}

/* Convert index into the slot of a given array index */
static inline unsigned int lrng_data_idx2slot(unsigned int idx)
{
	return idx & LRNG_DATA_SLOTS_MASK;
}

/* Convert value into slot value */
static inline unsigned int lrng_data_slot_val(unsigned int val,
					      unsigned int slot)
{
	return val << lrng_data_slot2bitindex(slot);
}
