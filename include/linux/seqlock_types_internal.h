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

#ifdef CONFIG_PREEMPT_RT

/*
 * Do not disable preemption for PREEMPT_RT. Check comment on top of
 * seqlock.h read_seqbegin() for rationale.
 */
#define __enforce_preemption_protection(s)			(false)

#else

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

#define __enforce_preemption_protection(s)				\
	__associated_lock_is_preemptible(s)

#endif /* CONFIG_PREEMPT_RT */

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
	if (__enforce_preemption_protection(s))				\
		preempt_disable();					\
									\
	raw_write_seqcount_t_begin(__to_seqcount_t(s));			\
} while (0)

#define do_raw_write_seqcount_end(s)					\
do {									\
	raw_write_seqcount_t_end(__to_seqcount_t(s));			\
									\
	if (__enforce_preemption_protection(s))				\
		preempt_enable();					\
} while (0)

#define do_write_seqcount_begin_nested(s, subclass)			\
do {									\
	__assert_associated_lock_held(s);				\
									\
	if (__enforce_preemption_protection(s))				\
		preempt_disable();					\
									\
	write_seqcount_t_begin_nested(__to_seqcount_t(s), subclass);	\
} while (0)

#define do_write_seqcount_begin(s)					\
do {									\
	__assert_associated_lock_held(s);				\
									\
	if (__enforce_preemption_protection(s))				\
		preempt_disable();					\
									\
	write_seqcount_t_begin(__to_seqcount_t(s));			\
} while (0)

#define do_write_seqcount_end(s)					\
do {									\
	write_seqcount_t_end(__to_seqcount_t(s));			\
									\
	if (__enforce_preemption_protection(s))				\
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

#ifdef CONFIG_PREEMPT_RT

/*
 * Check comment on top of read_seqbegin() for rationale.
 *
 * @s: pointer to seqcount_t or any of the seqcount_locktype_t variants
 */
#define __rt_lock_unlock_associated_sleeping_lock(s)			\
do {									\
	if (__same_type(*(s), seqcount_t)  ||				\
	    __same_type(*(s), seqcount_raw_spinlock_t))	{		\
		break;	/* NOP */					\
	}								\
									\
	if (__same_type(*(s), seqcount_spinlock_t)) {			\
		spin_lock(((seqcount_spinlock_t *) s)->lock);		\
		spin_unlock(((seqcount_spinlock_t *) s)->lock);		\
	} else if (__same_type(*(s), seqcount_rwlock_t)) {		\
		read_lock(((seqcount_rwlock_t *) s)->lock);		\
		read_unlock(((seqcount_rwlock_t *) s)->lock);		\
	} else if (__same_type(*(s), seqcount_mutex_t)) {		\
		mutex_lock(((seqcount_mutex_t *) s)->lock);		\
		mutex_unlock(((seqcount_mutex_t *) s)->lock);		\
	} else if (__same_type(*(s), seqcount_ww_mutex_t)) {		\
		ww_mutex_lock(((seqcount_ww_mutex_t *) s)->lock, NULL); \
		ww_mutex_unlock(((seqcount_ww_mutex_t *) s)->lock);	\
	} else								\
		BUILD_BUG_ON_MSG(1, "Unknown seqcount type");		\
} while (0)

/*
 * @s: pointer to seqcount_t or any of the seqcount_locktype_t variants
 *
 * After the lock-unlock operation, re-read the sequence counter since
 * the writer made progress.
 *
 * Do not lock-unlock the seqcount associated sleeping lock again if the
 * second counter read value is odd. If the first counter read was odd
 * because the reader preempted the write-side critical section, the
 * second odd value read must've been the result of a writer running on
 * a parallel core instead.
 */
#define __raw_read_seqcount(s)						\
({									\
	unsigned seq = READ_ONCE(__to_seqcount_t(s)->sequence);		\
									\
	if (unlikely(seq & 1))						\
		__rt_lock_unlock_associated_sleeping_lock(s);		\
									\
	/* no read barrier, no counter stabilization, no lockdep */	\
	READ_ONCE(__to_seqcount_t(s)->sequence);			\
})

#define do___read_seqcount_begin(s)					\
({									\
	unsigned seq;							\
									\
	do {								\
		seq = __raw_read_seqcount(s);				\
		cpu_relax();						\
	} while (unlikely(seq & 1));					\
									\
	/* no read barrier, with stabilized counter, no lockdep */	\
	seq;								\
})

#define do_raw_read_seqcount(s)						\
({									\
	unsigned seq = __raw_read_seqcount(s);				\
									\
	smp_rmb();							\
									\
	/* with read barrier, no counter stabilization, no lockdep */	\
	seq;								\
})

#define do_raw_seqcount_begin(s)					\
({									\
	/* with read barrier, no counter stabilization, no lockdep */	\
	(do_raw_read_seqcount(s) & ~1);					\
})

#define do_raw_read_seqcount_begin(s)					\
({									\
	unsigned seq = do___read_seqcount_begin(s);			\
									\
	smp_rmb();							\
									\
	/* with read barrier, with stabilized counter, no lockdep */	\
	seq;								\
})

#define do_read_seqcount_begin(s)					\
({									\
	seqcount_lockdep_reader_access(__to_seqcount_t(s));		\
									\
	/* with read barrier, stabilized counter, and lockdep */	\
	do_raw_read_seqcount_begin(s);					\
})

#else /* !CONFIG_PREEMPT_RT */

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

#endif /* CONFIG_PREEMPT_RT */

/*
 * Latch sequence counters allows interruptible, preemptible, writer
 * sections. There is no need for a special PREEMPT_RT implementation.
 */
#define do_raw_read_seqcount_latch(s)					\
	raw_read_seqcount_t_latch(__to_seqcount_t(s))

#define do___read_seqcount_retry(s, start)				\
	__read_seqcount_t_retry(__to_seqcount_t(s), start)

#define do_read_seqcount_retry(s, start)				\
	read_seqcount_t_retry(__to_seqcount_t(s), start)

#endif /* __LINUX_SEQLOCK_TYPES_INTERNAL_H */
