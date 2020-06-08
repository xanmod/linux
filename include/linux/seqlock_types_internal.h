/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_SEQLOCK_TYPES_INTERNAL_H
#define __LINUX_SEQLOCK_TYPES_INTERNAL_H

/*
 * Sequence counters with associated locks
 *
 * Copyright (C) 2020 Linutronix GmbH
 */

#ifndef __LINUX_SEQLOCK_H
#error This is an INTERNAL header; it must only be included by seqlock.h
#endif

#include <linux/mutex.h>
#include <linux/rwlock.h>
#include <linux/spinlock.h>
#include <linux/ww_mutex.h>

/*
 * @s: pointer to seqcount_t or any of the seqcount_locktype_t variants
 */
#define __to_seqcount_t(s)						\
({									\
	seqcount_t *seq;						\
									\
	if (__same_type(*(s), seqcount_t))				\
		seq = (seqcount_t *)(s);				\
	else if (__same_type(*(s), seqcount_spinlock_t))		\
		seq = &((seqcount_spinlock_t *)(s))->seqcount;		\
	else if (__same_type(*(s), seqcount_raw_spinlock_t))		\
		seq = &((seqcount_raw_spinlock_t *)(s))->seqcount;	\
	else if (__same_type(*(s), seqcount_rwlock_t))			\
		seq = &((seqcount_rwlock_t *)(s))->seqcount;		\
	else if (__same_type(*(s), seqcount_mutex_t))			\
		seq = &((seqcount_mutex_t *)(s))->seqcount;		\
	else if (__same_type(*(s), seqcount_ww_mutex_t))		\
		seq = &((seqcount_ww_mutex_t *)(s))->seqcount;		\
	else								\
		BUILD_BUG_ON_MSG(1, "Unknown seqcount type");		\
									\
	seq;								\
})

/*
 *	seqcount_LOCKTYPE_t -- write APIs
 *
 * For associated lock types which do not implicitly disable preemption,
 * enforce preemption protection in the write side functions.
 *
 * Never use lockdep for the raw write variants.
 */

#define __associated_lock_is_preemptible(s)				\
({									\
	bool ret;							\
									\
	if (__same_type(*(s), seqcount_t) ||				\
	    __same_type(*(s), seqcount_spinlock_t) ||			\
	    __same_type(*(s), seqcount_raw_spinlock_t) ||		\
	    __same_type(*(s), seqcount_rwlock_t)) {			\
		ret = false;						\
	} else if (__same_type(*(s), seqcount_mutex_t) ||		\
		   __same_type(*(s), seqcount_ww_mutex_t)) {		\
		ret = true;						\
	} else								\
		BUILD_BUG_ON_MSG(1, "Unknown seqcount type");		\
									\
	ret;								\
})

#ifdef CONFIG_LOCKDEP

#define __assert_associated_lock_held(s)				\
do {									\
	if (__same_type(*(s), seqcount_t))				\
		break;							\
									\
	if (__same_type(*(s), seqcount_spinlock_t))			\
		lockdep_assert_held(((seqcount_spinlock_t *)(s))->lock);\
	else if (__same_type(*(s), seqcount_raw_spinlock_t))		\
		lockdep_assert_held(((seqcount_raw_spinlock_t *)(s))->lock);	\
	else if (__same_type(*(s), seqcount_rwlock_t))			\
		lockdep_assert_held_write(((seqcount_rwlock_t *)(s))->lock);	\
	else if (__same_type(*(s), seqcount_mutex_t))			\
		lockdep_assert_held(((seqcount_mutex_t *)(s))->lock);	\
	else if (__same_type(*(s), seqcount_ww_mutex_t))		\
		lockdep_assert_held(&((seqcount_ww_mutex_t *)(s))->lock->base);	\
	else								\
		BUILD_BUG_ON_MSG(1, "Unknown seqcount type");		\
} while (0)

#else

#define __assert_associated_lock_held(s)				\
do {									\
	(void) __to_seqcount_t(s);					\
} while (0)

#endif /* CONFIG_LOCKDEP */

#define do_raw_write_seqcount_begin(s)					\
do {									\
	if (__associated_lock_is_preemptible(s))			\
		preempt_disable();					\
									\
	raw_write_seqcount_t_begin(__to_seqcount_t(s));			\
} while (0)

#define do_raw_write_seqcount_end(s)					\
do {									\
	raw_write_seqcount_t_end(__to_seqcount_t(s));			\
									\
	if (__associated_lock_is_preemptible(s))			\
		preempt_enable();					\
} while (0)

#define do_write_seqcount_begin_nested(s, subclass)			\
do {									\
	__assert_associated_lock_held(s);				\
									\
	if (__associated_lock_is_preemptible(s))			\
		preempt_disable();					\
									\
	write_seqcount_t_begin_nested(__to_seqcount_t(s), subclass);	\
} while (0)

#define do_write_seqcount_begin(s)					\
do {									\
	__assert_associated_lock_held(s);				\
									\
	if (__associated_lock_is_preemptible(s))			\
		preempt_disable();					\
									\
	write_seqcount_t_begin(__to_seqcount_t(s));			\
} while (0)

#define do_write_seqcount_end(s)					\
do {									\
	write_seqcount_t_end(__to_seqcount_t(s));			\
									\
	if (__associated_lock_is_preemptible(s))			\
		preempt_enable();					\
} while (0)

#define do_write_seqcount_invalidate(s)					\
	write_seqcount_t_invalidate(__to_seqcount_t(s))

#define do_raw_write_seqcount_barrier(s)				\
	raw_write_seqcount_t_barrier(__to_seqcount_t(s))

/*
 * Latch sequence counters write side critical sections don't need to
 * run with preemption disabled. Check @raw_write_seqcount_latch().
 */
#define do_raw_write_seqcount_latch(s)					\
	raw_write_seqcount_t_latch(__to_seqcount_t(s))

/*
 *	seqcount_LOCKTYPE_t -- read APIs
 */

#define do___read_seqcount_begin(s)					\
	__read_seqcount_t_begin(__to_seqcount_t(s))

#define do_raw_read_seqcount(s)						\
	raw_read_seqcount_t(__to_seqcount_t(s))

#define do_raw_seqcount_begin(s)					\
	raw_seqcount_t_begin(__to_seqcount_t(s))

#define do_raw_read_seqcount_begin(s)					\
	raw_read_seqcount_t_begin(__to_seqcount_t(s))

#define do_read_seqcount_begin(s)					\
	read_seqcount_t_begin(__to_seqcount_t(s))

#define do_raw_read_seqcount_latch(s)					\
	raw_read_seqcount_t_latch(__to_seqcount_t(s))

#define do___read_seqcount_retry(s, start)				\
	__read_seqcount_t_retry(__to_seqcount_t(s), start)

#define do_read_seqcount_retry(s, start)				\
	read_seqcount_t_retry(__to_seqcount_t(s), start)

#endif /* __LINUX_SEQLOCK_TYPES_INTERNAL_H */
