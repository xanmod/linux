/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_SEQLOCK_H
#define __LINUX_SEQLOCK_H

/*
 * seqcount_t / seqlock_t - a reader-writer consistency mechanism with
 * lockless readers (read-only retry loops), and no writer starvation.
 *
 * See Documentation/locking/seqlock.rst for full description.
 *
 * Copyrights:
 * - Based on x86_64 vsyscall gettimeofday: Keith Owens, Andrea Arcangeli
 */

#include <linux/spinlock.h>
#include <linux/preempt.h>
#include <linux/lockdep.h>
#include <linux/compiler.h>
#include <asm/processor.h>

/*
 * Sequence counters (seqcount_t)
 *
 * This is the raw counting mechanism, without any writer protection.
 *
 * Write side critical sections must be serialized and non-preemptible.
 *
 * If readers can be invoked from hardirq or softirq contexts,
 * interrupts or bottom halves must also be respectively disabled before
 * entering the write section.
 *
 * This mechanism can't be used if the protected data contains pointers,
 * as the writer can invalidate a pointer that a reader is following.
 *
 * If the write serialization mechanism is one of the common kernel
 * locking primitives, use a sequence counter with associated lock
 * (seqcount_LOCKTYPE_t) instead.
 *
 * If it's desired to automatically handle the sequence counter writer
 * serialization and non-preemptibility requirements, use a sequential
 * lock (seqlock_t) instead.
 *
 * See Documentation/locking/seqlock.rst
 */
typedef struct seqcount {
	unsigned sequence;
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif
} seqcount_t;

static inline void __seqcount_init(seqcount_t *s, const char *name,
					  struct lock_class_key *key)
{
	/*
	 * Make sure we are not reinitializing a held lock:
	 */
	lockdep_init_map(&s->dep_map, name, key, 0);
	s->sequence = 0;
}

#ifdef CONFIG_DEBUG_LOCK_ALLOC
# define SEQCOUNT_DEP_MAP_INIT(lockname) \
		.dep_map = { .name = #lockname } \

/**
 * seqcount_init() - runtime initializer for seqcount_t
 * @s: Pointer to the &typedef seqcount_t instance
 */
# define seqcount_init(s)				\
	do {						\
		static struct lock_class_key __key;	\
		__seqcount_init((s), #s, &__key);	\
	} while (0)

static inline void seqcount_lockdep_reader_access(const seqcount_t *s)
{
	seqcount_t *l = (seqcount_t *)s;
	unsigned long flags;

	local_irq_save(flags);
	seqcount_acquire_read(&l->dep_map, 0, 0, _RET_IP_);
	seqcount_release(&l->dep_map, _RET_IP_);
	local_irq_restore(flags);
}

#else
# define SEQCOUNT_DEP_MAP_INIT(lockname)
# define seqcount_init(s) __seqcount_init(s, NULL, NULL)
# define seqcount_lockdep_reader_access(x)
#endif

/**
 * SEQCNT_ZERO() - static initializer for seqcount_t
 * @name: Name of the &typedef seqcount_t instance
 */
#define SEQCNT_ZERO(name) { .sequence = 0, SEQCOUNT_DEP_MAP_INIT(name) }

/**
 * __read_seqcount_begin() - begin a seq-read critical section (without barrier)
 * @s: Pointer to &typedef seqcount_t or any of the seqcount_locktype_t variants
 * Returns: count to be passed to read_seqcount_retry
 *
 * __read_seqcount_begin is like read_seqcount_begin, but has no smp_rmb()
 * barrier. Callers should ensure that smp_rmb() or equivalent ordering is
 * provided before actually loading any of the variables that are to be
 * protected in this critical section.
 *
 * Use carefully, only in critical code, and comment how the barrier is
 * provided.
 */
#define __read_seqcount_begin(s)	do___read_seqcount_begin(s)

static inline unsigned __read_seqcount_t_begin(const seqcount_t *s)
{
	unsigned ret;

repeat:
	ret = READ_ONCE(s->sequence);
	if (unlikely(ret & 1)) {
		cpu_relax();
		goto repeat;
	}
	return ret;
}

/**
 * raw_read_seqcount() - Read the raw seqcount
 * @s: Pointer to &typedef seqcount_t or any of the seqcount_locktype_t variants
 * Returns: count to be passed to read_seqcount_retry
 *
 * raw_read_seqcount opens a read critical section of the given
 * seqcount_t, without any lockdep checks and without checking or
 * masking the sequence counter LSB. Calling code is responsible for
 * handling that.
 */
#define raw_read_seqcount(s)	do_raw_read_seqcount(s)

static inline unsigned raw_read_seqcount_t(const seqcount_t *s)
{
	unsigned ret = READ_ONCE(s->sequence);
	smp_rmb();
	return ret;
}

/**
 * raw_read_seqcount_begin() - start seq-read critical section w/o lockdep
 * @s: Pointer to &typedef seqcount_t or any of the seqcount_locktype_t variants
 * Returns: count to be passed to read_seqcount_retry
 *
 * raw_read_seqcount_begin opens a read critical section of the given
 * seqcount_t, but without any lockdep checking. Validity of the read
 * section must be checked with read_seqcount_retry().
 */
#define raw_read_seqcount_begin(s)	do_raw_read_seqcount_begin(s)

static inline unsigned raw_read_seqcount_t_begin(const seqcount_t *s)
{
	unsigned ret = __read_seqcount_t_begin(s);
	smp_rmb();
	return ret;
}

/**
 * read_seqcount_begin() - begin a seq-read critical section
 * @s: pointer to &typedef seqcount_t or any of the seqcount_locktype_t variants
 * Returns: count to be passed to read_seqcount_retry
 *
 * read_seqcount_begin opens a read critical section of the given
 * seqcount_t. Validity of the read section must be checked with
 * read_seqcount_retry().
 */
#define read_seqcount_begin(s)	do_read_seqcount_begin(s)

static inline unsigned read_seqcount_t_begin(const seqcount_t *s)
{
	seqcount_lockdep_reader_access(s);
	return raw_read_seqcount_t_begin(s);
}

/**
 * raw_seqcount_begin() - begin a seq-read critical section
 * @s: pointer to &typedef seqcount_t or any of the seqcount_locktype_t variants
 * Returns: count to be passed to read_seqcount_retry
 *
 * raw_seqcount_begin opens a read critical section of the given seqcount_t.
 * Validity of the critical section is tested by checking read_seqcount_retry
 * function.
 *
 * Unlike read_seqcount_begin(), this function will not wait for the count
 * to stabilize. If a writer is active when we begin, we will fail the
 * read_seqcount_retry() instead of stabilizing at the beginning of the
 * critical section.
 */
#define raw_seqcount_begin(s)	do_raw_seqcount_begin(s)

static inline unsigned raw_seqcount_t_begin(const seqcount_t *s)
{
	unsigned ret = READ_ONCE(s->sequence);
	smp_rmb();
	return ret & ~1;
}

/**
 * __read_seqcount_retry() - end a seq-read critical section (without barrier)
 * @s: pointer to &typedef seqcount_t or any of the seqcount_locktype_t variants
 * @start: count, from read_seqcount_begin
 * Returns: 1 if retry is required, else 0
 *
 * __read_seqcount_retry is like read_seqcount_retry, but has no smp_rmb()
 * barrier. Callers should ensure that smp_rmb() or equivalent ordering is
 * provided before actually loading any of the variables that are to be
 * protected in this critical section.
 *
 * Use carefully, only in critical code, and comment how the barrier is
 * provided.
 */
#define __read_seqcount_retry(s, start)	do___read_seqcount_retry(s, start)

static inline int __read_seqcount_t_retry(const seqcount_t *s, unsigned start)
{
	return unlikely(s->sequence != start);
}

/**
 * read_seqcount_retry() - end a seq-read critical section
 * @s: pointer to &typedef seqcount_t or any of the seqcount_locktype_t variants
 * @start: count, from read_seqcount_begin
 * Returns: 1 if retry is required, else 0
 *
 * read_seqcount_retry closes a read critical section of given seqcount_t.
 * If the critical section was invalid, it must be ignored (and typically
 * retried).
 */
#define read_seqcount_retry(s, start)	do_read_seqcount_retry(s, start)

static inline int read_seqcount_t_retry(const seqcount_t *s, unsigned start)
{
	smp_rmb();
	return __read_seqcount_t_retry(s, start);
}

#define raw_write_seqcount_begin(s)	do_raw_write_seqcount_begin(s)

static inline void raw_write_seqcount_t_begin(seqcount_t *s)
{
	s->sequence++;
	smp_wmb();
}

#define raw_write_seqcount_end(s)	do_raw_write_seqcount_end(s)

static inline void raw_write_seqcount_t_end(seqcount_t *s)
{
	smp_wmb();
	s->sequence++;
}

/**
 * raw_write_seqcount_barrier() - do a seq write barrier
 * @s: Pointer to &typedef seqcount_t or any of the seqcount_locktype_t variants
 *
 * This can be used to provide an ordering guarantee instead of the
 * usual consistency guarantee. It is one wmb cheaper, because we can
 * collapse the two back-to-back wmb()s::
 *
 *      seqcount_t seq;
 *      bool X = true, Y = false;
 *
 *      void read(void)
 *      {
 *              bool x, y;
 *
 *              do {
 *                      int s = read_seqcount_begin(&seq);
 *
 *                      x = X; y = Y;
 *
 *              } while (read_seqcount_retry(&seq, s));
 *
 *              BUG_ON(!x && !y);
 *      }
 *
 *      void write(void)
 *      {
 *              Y = true;
 *
 *              raw_write_seqcount_barrier(seq);
 *
 *              X = false;
 *      }
 */
#define raw_write_seqcount_barrier(s)	do_raw_write_seqcount_barrier(s)

static inline void raw_write_seqcount_t_barrier(seqcount_t *s)
{
	s->sequence++;
	smp_wmb();
	s->sequence++;
}

/**
 * raw_read_seqcount_latch() - pick even or odd seqcount latch data copy
 * @s: pointer to &typedef seqcount_t or any of the seqcount_locktype_t variants
 *
 * Use seqcount latching to switch between two storage places with
 * sequence protection to allow interruptible, preemptible, writer
 * sections.
 *
 * Check raw_write_seqcount_latch() for more details and a full reader
 * and writer usage example.
 *
 * Return: sequence counter. Use the lowest bit as index for picking
 * which data copy to read. Full counter must then be checked with
 * read_seqcount_retry().
 */
#define raw_read_seqcount_latch(s)	do_raw_read_seqcount_latch(s)

static inline int raw_read_seqcount_t_latch(seqcount_t *s)
{
	/* Pairs with the first smp_wmb() in raw_write_seqcount_latch() */
	int seq = READ_ONCE(s->sequence); /* ^^^ */
	return seq;
}

/**
 * raw_write_seqcount_latch() - redirect readers to even/odd copy
 * @s: pointer to &typedef seqcount_t or any of the seqcount_locktype_t variants
 *
 * The latch technique is a multiversion concurrency control method that allows
 * queries during non-atomic modifications. If you can guarantee queries never
 * interrupt the modification -- e.g. the concurrency is strictly between CPUs
 * -- you most likely do not need this.
 *
 * Where the traditional RCU/lockless data structures rely on atomic
 * modifications to ensure queries observe either the old or the new state the
 * latch allows the same for non-atomic updates. The trade-off is doubling the
 * cost of storage; we have to maintain two copies of the entire data
 * structure.
 *
 * Very simply put: we first modify one copy and then the other. This ensures
 * there is always one copy in a stable state, ready to give us an answer.
 *
 * The basic form is a data structure like::
 *
 *	struct latch_struct {
 *		seqcount_t		seq;
 *		struct data_struct	data[2];
 *	};
 *
 * Where a modification, which is assumed to be externally serialized, does the
 * following::
 *
 *	void latch_modify(struct latch_struct *latch, ...)
 *	{
 *		smp_wmb();	// Ensure that the last data[1] update is visible
 *		latch->seq++;
 *		smp_wmb();	// Ensure that the seqcount update is visible
 *
 *		modify(latch->data[0], ...);
 *
 *		smp_wmb();	// Ensure that the data[0] update is visible
 *		latch->seq++;
 *		smp_wmb();	// Ensure that the seqcount update is visible
 *
 *		modify(latch->data[1], ...);
 *	}
 *
 * The query will have a form like::
 *
 *	struct entry *latch_query(struct latch_struct *latch, ...)
 *	{
 *		struct entry *entry;
 *		unsigned seq, idx;
 *
 *		do {
 *			seq = raw_read_seqcount_latch(&latch->seq);
 *
 *			idx = seq & 0x01;
 *			entry = data_query(latch->data[idx], ...);
 *
 *			// read_seqcount_retry() includes necessary smp_rmb()
 *		} while (read_seqcount_retry(&latch->seq, seq);
 *
 *		return entry;
 *	}
 *
 * So during the modification, queries are first redirected to data[1]. Then we
 * modify data[0]. When that is complete, we redirect queries back to data[0]
 * and we can modify data[1].
 *
 * NOTE:
 *
 *	The non-requirement for atomic modifications does _NOT_ include
 *	the publishing of new entries in the case where data is a dynamic
 *	data structure.
 *
 *	An iteration might start in data[0] and get suspended long enough
 *	to miss an entire modification sequence, once it resumes it might
 *	observe the new entry.
 *
 * NOTE:
 *
 *	When data is a dynamic data structure; one should use regular RCU
 *	patterns to manage the lifetimes of the objects within.
 */
#define raw_write_seqcount_latch(s)	do_raw_write_seqcount_latch(s)

static inline void raw_write_seqcount_t_latch(seqcount_t *s)
{
       smp_wmb();      /* prior stores before incrementing "sequence" */
       s->sequence++;
       smp_wmb();      /* increment "sequence" before following stores */
}

#define write_seqcount_begin_nested(s, subclass)		\
	do_write_seqcount_begin_nested(s, subclass)

static inline void write_seqcount_t_begin_nested(seqcount_t *s, int subclass)
{
	raw_write_seqcount_t_begin(s);
	seqcount_acquire(&s->dep_map, subclass, 0, _RET_IP_);
}

/**
 * write_seqcount_begin() - start a seqcount write-side critical section
 * @s: Pointer to &typedef seqcount_t
 *
 * write_seqcount_begin opens a write-side critical section of the given
 * seqcount. Seqcount write-side critical sections must be externally
 * serialized and non-preemptible.
 */
#define write_seqcount_begin(s)		do_write_seqcount_begin(s)

static inline void write_seqcount_t_begin(seqcount_t *s)
{
	write_seqcount_t_begin_nested(s, 0);
}

/**
 * write_seqcount_end() - end a seqcount write-side critical section
 * @s: Pointer to &typedef seqcount_t
 *
 * The write section must've been opened with write_seqcount_begin().
 */
#define write_seqcount_end(s)		do_write_seqcount_end(s)

static inline void write_seqcount_t_end(seqcount_t *s)
{
	seqcount_release(&s->dep_map, _RET_IP_);
	raw_write_seqcount_t_end(s);
}

/**
 * write_seqcount_invalidate() - invalidate in-progress read-side seq operations
 * @s: Pointer to &typedef seqcount_t or any of the seqcount_locktype_t variants
 *
 * After write_seqcount_invalidate, no read-side seq operations will complete
 * successfully and see data older than this.
 */
#define write_seqcount_invalidate(s)	do_write_seqcount_invalidate(s)

static inline void write_seqcount_t_invalidate(seqcount_t *s)
{
	smp_wmb();
	s->sequence+=2;
}

/*
 * Sequence counters with associated locks (seqcount_LOCKTYPE_t)
 *
 * A sequence counter which associates the lock used for writer
 * serialization at initialization time. This enables lockdep to validate
 * that the write side critical section is properly serialized.
 *
 * For associated locks which do not implicitly disable preemption,
 * preemption protection is enforced in the write side function.
 *
 * See Documentation/locking/seqlock.rst
 */

#if defined(CONFIG_LOCKDEP) || defined(CONFIG_PREEMPT_RT)
#define SEQCOUNT_ASSOC_LOCK
#endif

/**
 * typedef seqcount_spinlock_t - sequence count with spinlock associated
 * @seqcount:		The real sequence counter
 * @lock:		Pointer to the associated spinlock
 *
 * A plain sequence counter with external writer synchronization by a
 * spinlock. The spinlock is associated to the sequence count in the
 * static initializer or init function. This enables lockdep to validate
 * that the write side critical section is properly serialized.
 */
typedef struct seqcount_spinlock {
	seqcount_t      seqcount;
#ifdef SEQCOUNT_ASSOC_LOCK
	spinlock_t	*lock;
#endif
} seqcount_spinlock_t;

#ifdef SEQCOUNT_ASSOC_LOCK

#define SEQCOUNT_LOCKTYPE_ZERO(seq_name, assoc_lock) {		\
	.seqcount	= SEQCNT_ZERO(seq_name.seqcount),	\
	.lock		= (assoc_lock),				\
}

/* Define as macro due to static lockdep key @ seqcount_init() */
#define seqcount_locktype_init(s, assoc_lock)			\
do {								\
	seqcount_init(&(s)->seqcount);				\
	(s)->lock = (assoc_lock);				\
} while (0)

#else /* !SEQCOUNT_ASSOC_LOCK */

#define SEQCOUNT_LOCKTYPE_ZERO(seq_name, assoc_lock) {		\
	.seqcount	= SEQCNT_ZERO(seq_name.seqcount),	\
}

#define seqcount_locktype_init(s, assoc_lock)			\
do {								\
	seqcount_init(&(s)->seqcount);				\
} while (0)

#endif /* SEQCOUNT_ASSOC_LOCK */

/**
 * SEQCNT_SPINLOCK_ZERO - static initializer for seqcount_spinlock_t
 * @name:	Name of the &typedef seqcount_spinlock_t instance
 * @lock:	Pointer to the associated spinlock
 */
#define SEQCNT_SPINLOCK_ZERO(name, lock)	\
	SEQCOUNT_LOCKTYPE_ZERO(name, lock)

/**
 * seqcount_spinlock_init - runtime initializer for seqcount_spinlock_t
 * @s:		Pointer to the &typedef seqcount_spinlock_t instance
 * @lock:	Pointer to the associated spinlock
 */
#define seqcount_spinlock_init(s, lock)		\
	seqcount_locktype_init(s, lock)

/**
 * typedef seqcount_raw_spinlock_t - sequence count with raw spinlock associated
 * @seqcount:		The real sequence counter
 * @lock:		Pointer to the associated raw spinlock
 *
 * A plain sequence counter with external writer synchronization by a
 * raw spinlock. The raw spinlock is associated to the sequence count in
 * the static initializer or init function. This enables lockdep to
 * validate that the write side critical section is properly serialized.
 */
typedef struct seqcount_raw_spinlock {
	seqcount_t      seqcount;
#ifdef SEQCOUNT_ASSOC_LOCK
	raw_spinlock_t	*lock;
#endif
} seqcount_raw_spinlock_t;

/**
 * SEQCNT_RAW_SPINLOCK_ZERO - static initializer for seqcount_raw_spinlock_t
 * @name:	Name of the &typedef seqcount_raw_spinlock_t instance
 * @lock:	Pointer to the associated raw_spinlock
 */
#define SEQCNT_RAW_SPINLOCK_ZERO(name, lock)	\
	SEQCOUNT_LOCKTYPE_ZERO(name, lock)

/**
 * seqcount_raw_spinlock_init - runtime initializer for seqcount_raw_spinlock_t
 * @s:		Pointer to the &typedef seqcount_raw_spinlock_t instance
 * @lock:	Pointer to the associated raw_spinlock
 */
#define seqcount_raw_spinlock_init(s, lock)	\
	seqcount_locktype_init(s, lock)

/**
 * typedef seqcount_rwlock_t - sequence count with rwlock associated
 * @seqcount:		The real sequence counter
 * @lock:		Pointer to the associated rwlock
 *
 * A plain sequence counter with external writer synchronization by a
 * rwlock. The rwlock is associated to the sequence count in the static
 * initializer or init function. This enables lockdep to validate that
 * the write side critical section is properly serialized.
 */
typedef struct seqcount_rwlock {
	seqcount_t      seqcount;
#ifdef SEQCOUNT_ASSOC_LOCK
	rwlock_t	*lock;
#endif
} seqcount_rwlock_t;

/**
 * SEQCNT_RWLOCK_ZERO - static initializer for seqcount_rwlock_t
 * @name:	Name of the &typedef seqcount_rwlock_t instance
 * @lock:	Pointer to the associated rwlock
 */
#define SEQCNT_RWLOCK_ZERO(name, lock)		\
	SEQCOUNT_LOCKTYPE_ZERO(name, lock)

/**
 * seqcount_rwlock_init - runtime initializer for seqcount_rwlock_t
 * @s:		Pointer to the &typedef seqcount_rwlock_t instance
 * @lock:	Pointer to the associated rwlock
 */
#define seqcount_rwlock_init(s, lock)		\
	seqcount_locktype_init(s, lock)

/**
 * typedef seqcount_mutex_t - sequence count with mutex associated
 * @seqcount:		The real sequence counter
 * @lock:		Pointer to the associated mutex
 *
 * A plain sequence counter with external writer synchronization by a
 * mutex. The mutex is associated to the sequence counter in the static
 * initializer or init function. This enables lockdep to validate that
 * the write side critical section is properly serialized.
 *
 * The write side API functions write_seqcount_begin()/end() automatically
 * disable and enable preemption when used with seqcount_mutex_t.
 */
typedef struct seqcount_mutex {
	seqcount_t      seqcount;
#ifdef SEQCOUNT_ASSOC_LOCK
	struct mutex	*lock;
#endif
} seqcount_mutex_t;

/**
 * SEQCNT_MUTEX_ZERO - static initializer for seqcount_mutex_t
 * @name:	Name of the &typedef seqcount_mutex_t instance
 * @lock:	Pointer to the associated mutex
 */
#define SEQCNT_MUTEX_ZERO(name, lock)		\
	SEQCOUNT_LOCKTYPE_ZERO(name, lock)

/**
 * seqcount_mutex_init - runtime initializer for seqcount_mutex_t
 * @s:		Pointer to the &typedef seqcount_mutex_t instance
 * @lock:	Pointer to the associated mutex
 */
#define seqcount_mutex_init(s, lock)		\
	seqcount_locktype_init(s, lock)

/**
 * typedef seqcount_ww_mutex_t - sequence count with ww_mutex associated
 * @seqcount:		The real sequence counter
 * @lock:		Pointer to the associated ww_mutex
 *
 * A plain sequence counter with external writer synchronization by a
 * ww_mutex. The ww_mutex is associated to the sequence counter in the static
 * initializer or init function. This enables lockdep to validate that
 * the write side critical section is properly serialized.
 *
 * The write side API functions write_seqcount_begin()/end() automatically
 * disable and enable preemption when used with seqcount_ww_mutex_t.
 */
typedef struct seqcount_ww_mutex {
	seqcount_t      seqcount;
#ifdef SEQCOUNT_ASSOC_LOCK
	struct ww_mutex	*lock;
#endif
} seqcount_ww_mutex_t;

/**
 * SEQCNT_WW_MUTEX_ZERO - static initializer for seqcount_ww_mutex_t
 * @name:	Name of the &typedef seqcount_ww_mutex_t instance
 * @lock:	Pointer to the associated ww_mutex
 */
#define SEQCNT_WW_MUTEX_ZERO(name, lock)	\
	SEQCOUNT_LOCKTYPE_ZERO(name, lock)

/**
 * seqcount_ww_mutex_init - runtime initializer for seqcount_ww_mutex_t
 * @s:		Pointer to the &typedef seqcount_ww_mutex_t instance
 * @lock:	Pointer to the associated ww_mutex
 */
#define seqcount_ww_mutex_init(s, lock)		\
	seqcount_locktype_init(s, lock)

#include <linux/seqlock_types_internal.h>

/*
 * Sequential locks (seqlock_t)
 *
 * Sequence counters with an embedded spinlock for writer serialization
 * and non-preemptibility.
 *
 * For more info, see:
 *   - Comments on top of seqcount_t
 *   - Documentation/locking/seqlock.rst
 */
typedef struct {
	struct seqcount seqcount;
	spinlock_t lock;
} seqlock_t;

#define __SEQLOCK_UNLOCKED(lockname)			\
	{						\
		.seqcount = SEQCNT_ZERO(lockname),	\
		.lock =	__SPIN_LOCK_UNLOCKED(lockname)	\
	}

/**
 * seqlock_init() - dynamic initializer for seqlock_t
 * @sl: Pointer to the &typedef seqlock_t instance
 */
#define seqlock_init(sl)				\
	do {						\
		seqcount_init(&(sl)->seqcount);		\
		spin_lock_init(&(sl)->lock);		\
	} while (0)

/**
 * DEFINE_SEQLOCK() - Define a statically-allocated seqlock_t
 * @sl: Name of the &typedef seqlock_t instance
 */
#define DEFINE_SEQLOCK(sl) \
		seqlock_t sl = __SEQLOCK_UNLOCKED(sl)

/**
 * read_seqbegin() - start a seqlock_t read-side critical section
 * @sl: Pointer to &typedef seqlock_t
 *
 * read_seqbegin opens a read side critical section of the given
 * seqlock_t. Validity of the critical section is tested by checking
 * read_seqretry().
 *
 * Return: count to be passed to read_seqretry()
 */

/*
 * For PREEMPT_RT, preemption cannot be disabled upon entering the write
 * side critical section. With disabled preemption:
 *
 *   - The writer cannot be preempted by a task with higher priority
 *
 *   - The writer cannot acquire a spinlock_t since it's a sleeping
 *     lock.  This would invalidate the existing, and non-PREEMPT_RT
 *     valid, code pattern of acquiring a spinlock_t inside the seqcount
 *     write side critical section.
 *
 * To remain preemptible, while avoiding a livelock caused by the reader
 * preempting the writer, use a different technique:
 *
 *   - If the sequence counter is even upon entering a read side
 *     section, then no writer is in progress, and the reader did not
 *     preempt any write side sections. It can continue.
 *
 *   - If the counter is odd, a writer is in progress and the reader may
 *     have preempted a write side section. Let the reader acquire the
 *     lock used for seqcount writer serialization, which is already
 *     held by the writer.
 *
 *     The higher-priority reader will block on the lock, and the
 *     lower-priority preempted writer will make progress until it
 *     finishes its write serialization lock critical section.
 *
 *     Once the reader has the writer serialization lock acquired, the
 *     writer is finished and the counter is even. Drop the writer
 *     serialization lock and re-read the sequence counter.
 *
 * This technique must be implemented for all PREEMPT_RT sleeping locks.
 */
#ifdef CONFIG_PREEMPT_RT

static inline unsigned read_seqbegin(const seqlock_t *sl)
{
	unsigned seq;

	seqcount_lockdep_reader_access(&sl->seqcount);

	do {
		seq = READ_ONCE(sl->seqcount.sequence);
		if (unlikely(seq & 1)) {
			seqlock_t *msl = (seqlock_t *)sl;
			spin_lock(&msl->lock);
			spin_unlock(&msl->lock);
		}
	} while (unlikely(seq & 1));

	smp_rmb();
	return seq;
}

#else /* !CONFIG_PREEMPT_RT */

static inline unsigned read_seqbegin(const seqlock_t *sl)
{
	return read_seqcount_t_begin(&sl->seqcount);
}

#endif

/**
 * read_seqretry() - end and validate a seqlock_t read side section
 * @sl: Pointer to &typedef seqlock_t
 * @start: count, from read_seqbegin()
 *
 * read_seqretry closes the given seqlock_t read side critical section,
 * and checks its validity. If the read section was invalid, it must be
 * ignored and retried.
 *
 * Return: 1 if a retry is required, 0 otherwise
 */
static inline unsigned read_seqretry(const seqlock_t *sl, unsigned start)
{
	return read_seqcount_t_retry(&sl->seqcount, start);
}

/**
 * write_seqlock() - start a seqlock_t write side critical section
 * @sl: Pointer to &typedef seqlock_t
 *
 * write_seqlock opens a write side critical section of the given
 * seqlock_t.  It also acquires the spinlock_t embedded inside the
 * sequential lock. All the seqlock_t write side critical sections are
 * thus automatically serialized and non-preemptible.
 *
 * Use the ``_irqsave`` and ``_bh`` variants instead if the read side
 * can be invoked from a hardirq or softirq context.
 *
 * The opened write side section must be closed with write_sequnlock().
 */
static inline void write_seqlock(seqlock_t *sl)
{
	spin_lock(&sl->lock);
	write_seqcount_t_begin(&sl->seqcount);
}

/**
 * write_sequnlock() - end a seqlock_t write side critical section
 * @sl: Pointer to &typedef seqlock_t
 *
 * write_sequnlock closes the (serialized and non-preemptible) write
 * side critical section of given seqlock_t.
 */
static inline void write_sequnlock(seqlock_t *sl)
{
	write_seqcount_t_end(&sl->seqcount);
	spin_unlock(&sl->lock);
}

/**
 * write_seqlock_bh() - start a softirqs-disabled seqlock_t write section
 * @sl: Pointer to &typedef seqlock_t
 *
 * ``_bh`` variant of write_seqlock(). Use only if the read side section
 * can be invoked from a softirq context.
 *
 * The opened write section must be closed with write_sequnlock_bh().
 */
static inline void write_seqlock_bh(seqlock_t *sl)
{
	spin_lock_bh(&sl->lock);
	write_seqcount_t_begin(&sl->seqcount);
}

/**
 * write_sequnlock_bh() - end a softirqs-disabled seqlock_t write section
 * @sl: Pointer to &typedef seqlock_t
 *
 * write_sequnlock_bh closes the serialized, non-preemptible,
 * softirqs-disabled, seqlock_t write side critical section opened with
 * write_seqlock_bh().
 */
static inline void write_sequnlock_bh(seqlock_t *sl)
{
	write_seqcount_t_end(&sl->seqcount);
	spin_unlock_bh(&sl->lock);
}

/**
 * write_seqlock_irq() - start a non-interruptible seqlock_t write side section
 * @sl: Pointer to &typedef seqlock_t
 *
 * This is the ``_irq`` variant of write_seqlock(). Use only if the read
 * section of given seqlock_t can be invoked from a hardirq context.
 */
static inline void write_seqlock_irq(seqlock_t *sl)
{
	spin_lock_irq(&sl->lock);
	write_seqcount_t_begin(&sl->seqcount);
}

/**
 * write_sequnlock_irq() - end a non-interruptible seqlock_t write side section
 * @sl: Pointer to &typedef seqlock_t
 *
 * ``_irq`` variant of write_sequnlock(). The write side section of
 * given seqlock_t must've been opened with write_seqlock_irq().
 */
static inline void write_sequnlock_irq(seqlock_t *sl)
{
	write_seqcount_t_end(&sl->seqcount);
	spin_unlock_irq(&sl->lock);
}

static inline unsigned long __write_seqlock_irqsave(seqlock_t *sl)
{
	unsigned long flags;

	spin_lock_irqsave(&sl->lock, flags);
	write_seqcount_t_begin(&sl->seqcount);

	return flags;
}

/**
 * write_seqlock_irqsave() - start a non-interruptible seqlock_t write section
 * @lock:  Pointer to &typedef seqlock_t
 * @flags: Stack-allocated storage for saving caller's local interrupt
 *         state, to be passed to write_sequnlock_irqrestore().
 *
 * ``_irqsave`` variant of write_seqlock(). Use if the read section of
 * given seqlock_t can be invoked from a hardirq context.
 *
 * The opened write section must be closed with write_sequnlock_irqrestore().
 */
#define write_seqlock_irqsave(lock, flags)				\
	do { flags = __write_seqlock_irqsave(lock); } while (0)

/**
 * write_sequnlock_irqrestore() - end non-interruptible seqlock_t write section
 * @sl:    Pointer to &typedef seqlock_t
 * @flags: Caller's saved interrupt state, from write_seqlock_irqsave()
 *
 * ``_irqrestore`` variant of write_sequnlock(). The write section of
 * given seqlock_t must've been opened with write_seqlock_irqsave().
 */
static inline void
write_sequnlock_irqrestore(seqlock_t *sl, unsigned long flags)
{
	write_seqcount_t_end(&sl->seqcount);
	spin_unlock_irqrestore(&sl->lock, flags);
}

/**
 * read_seqlock_excl() - begin a seqlock_t locking reader critical section
 * @sl: Pointer to &typedef seqlock_t
 *
 * read_seqlock_excl opens a locking reader critical section for the
 * given seqlock_t. A locking reader exclusively locks out other writers
 * and other *locking* readers, but doesn't update the sequence number.
 *
 * Locking readers act like a normal spin_lock()/spin_unlock().
 *
 * The opened read side section must be closed with read_sequnlock_excl().
 */
static inline void read_seqlock_excl(seqlock_t *sl)
{
	spin_lock(&sl->lock);
}

/**
 * read_sequnlock_excl() - end a seqlock_t locking reader critical section
 * @sl: Pointer to &typedef seqlock_t
 *
 * read_sequnlock_excl closes the locking reader critical section opened
 * with read_seqlock_excl().
 */
static inline void read_sequnlock_excl(seqlock_t *sl)
{
	spin_unlock(&sl->lock);
}

/**
 * read_seqbegin_or_lock() - begin a seqlock_t lockless or locking reader
 * @lock: Pointer to &typedef seqlock_t
 * @seq : Marker and return parameter. If the passed value is even, the
 * reader will become a *lockless* seqlock_t sequence counter reader as
 * in read_seqbegin(). If the passed value is odd, the reader will
 * become a fully locking reader, as in read_seqlock_excl().  In the
 * first call to read_seqbegin_or_lock(), the caller **must** initialize
 * and pass an even value to @seq so a lockless read is optimistically
 * tried first.
 *
 * read_seqbegin_or_lock is an API designed to optimistically try a
 * normal lockless seqlock_t read section first, as in read_seqbegin().
 * If an odd counter is found, the normal lockless read trial has
 * failed, and the next reader iteration transforms to a full seqlock_t
 * locking reader as in read_seqlock_excl().
 *
 * This is typically used to avoid lockless seqlock_t readers starvation
 * (too much retry loops) in the case of a sharp spike in write
 * activity.
 *
 * The opened read section must be closed with done_seqretry().  Check
 * Documentation/locking/seqlock.rst for template example code.
 *
 * Return: The encountered sequence counter value, returned through the
 * @seq parameter, which is overloaded as a return parameter. The
 * returned value must be checked with need_seqretry(). If the read
 * section must be retried, the returned value must also be passed to
 * the @seq parameter of the next read_seqbegin_or_lock() iteration.
 */
static inline void read_seqbegin_or_lock(seqlock_t *lock, int *seq)
{
	if (!(*seq & 1))	/* Even */
		*seq = read_seqbegin(lock);
	else			/* Odd */
		read_seqlock_excl(lock);
}

/**
 * need_seqretry() - validate seqlock_t "locking or lockless" reader section
 * @lock: Pointer to &typedef seqlock_t
 * @seq: count, from read_seqbegin_or_lock()
 *
 * need_seqretry checks if the seqlock_t read-side critical section
 * started with read_seqbegin_or_lock() is valid. If it was not, the
 * caller must retry the read-side section.
 *
 * Return: 1 if a retry is required, 0 otherwise
 */
static inline int need_seqretry(seqlock_t *lock, int seq)
{
	return !(seq & 1) && read_seqretry(lock, seq);
}

/**
 * done_seqretry() - end seqlock_t "locking or lockless" reader section
 * @lock: Pointer to &typedef seqlock_t
 * @seq: count, from read_seqbegin_or_lock()
 *
 * done_seqretry finishes the seqlock_t read side critical section
 * started by read_seqbegin_or_lock(). The read section must've been
 * already validated with need_seqretry().
 */
static inline void done_seqretry(seqlock_t *lock, int seq)
{
	if (seq & 1)
		read_sequnlock_excl(lock);
}

/**
 * read_seqlock_excl_bh() - start a locking reader seqlock_t section
 *			    with softirqs disabled
 * @sl: Pointer to &typedef seqlock_t
 *
 * ``_bh`` variant of read_seqlock_excl(). Use this variant if the
 * seqlock_t write side section, *or other read sections*, can be
 * invoked from a softirq context
 *
 * The opened section must be closed with read_sequnlock_excl_bh().
 */
static inline void read_seqlock_excl_bh(seqlock_t *sl)
{
	spin_lock_bh(&sl->lock);
}

/**
 * read_sequnlock_excl_bh() - stop a seqlock_t softirq-disabled locking
 *			      reader section
 * @sl: Pointer to &typedef seqlock_t
 *
 * ``_bh`` variant of read_sequnlock_excl(). The closed section must've
 * been opened with read_seqlock_excl_bh().
 */
static inline void read_sequnlock_excl_bh(seqlock_t *sl)
{
	spin_unlock_bh(&sl->lock);
}

/**
 * read_seqlock_excl_irq() - start a non-interruptible seqlock_t locking
 *			     reader section
 * @sl: Pointer to &typedef seqlock_t
 *
 * ``_irq`` variant of read_seqlock_excl(). Use this only if the
 * seqlock_t write side critical section, *or other read side sections*,
 * can be invoked from a hardirq context.
 *
 * The opened read section must be closed with read_sequnlock_excl_irq().
 */
static inline void read_seqlock_excl_irq(seqlock_t *sl)
{
	spin_lock_irq(&sl->lock);
}

/**
 * read_sequnlock_excl_irq() - end an interrupts-disabled seqlock_t
 *                             locking reader section
 * @sl: Pointer to &typedef seqlock_t
 *
 * ``_irq`` variant of read_sequnlock_excl(). The closed section must've
 * been opened with read_seqlock_excl_irq().
 */
static inline void read_sequnlock_excl_irq(seqlock_t *sl)
{
	spin_unlock_irq(&sl->lock);
}

static inline unsigned long __read_seqlock_excl_irqsave(seqlock_t *sl)
{
	unsigned long flags;

	spin_lock_irqsave(&sl->lock, flags);
	return flags;
}

/**
 * read_seqlock_excl_irqsave() - start a non-interruptible seqlock_t
 *				 locking reader section
 * @lock: Pointer to &typedef seqlock_t
 * @flags: Stack-allocated storage for saving caller's local interrupt
 *         state, to be passed to read_sequnlock_excl_irqrestore().
 *
 * ``_irqsave`` variant of read_seqlock_excl(). Use this only if the
 * seqlock_t write side critical section, *or other read side sections*,
 * can be invoked from a hardirq context.
 *
 * Opened section must be closed with read_sequnlock_excl_irqrestore().
 */
#define read_seqlock_excl_irqsave(lock, flags)				\
	do { flags = __read_seqlock_excl_irqsave(lock); } while (0)

/**
 * read_sequnlock_excl_irqrestore() - end non-interruptible seqlock_t
 *				      locking reader section
 * @sl: Pointer to &typedef seqlock_t
 * @flags: Caller's saved interrupt state, from
 *	   read_seqlock_excl_irqsave()
 *
 * ``_irqrestore`` variant of read_sequnlock_excl(). The closed section
 * must've been opened with read_seqlock_excl_irqsave().
 */
static inline void
read_sequnlock_excl_irqrestore(seqlock_t *sl, unsigned long flags)
{
	spin_unlock_irqrestore(&sl->lock, flags);
}

/**
 * read_seqbegin_or_lock_irqsave() - begin a seqlock_t lockless reader, or
 *                                   a non-interruptible locking reader
 * @lock: Pointer to &typedef seqlock_t
 * @seq: Marker and return parameter. Check read_seqbegin_or_lock().
 *
 * This is the ``_irqsave`` variant of read_seqbegin_or_lock(). Use if
 * the seqlock_t write side critical section, *or other read side sections*,
 * can be invoked from hardirq context.
 *
 * The validity of the read section must be checked with need_seqretry().
 * The opened section must be closed with done_seqretry_irqrestore().
 *
 * Return:
 *
 *   1. The saved local interrupts state in case of a locking reader, to be
 *      passed to done_seqretry_irqrestore().
 *
 *   2. The encountered sequence counter value, returned through @seq which
 *      is overloaded as a return parameter. Check read_seqbegin_or_lock().
 */
static inline unsigned long
read_seqbegin_or_lock_irqsave(seqlock_t *lock, int *seq)
{
	unsigned long flags = 0;

	if (!(*seq & 1))	/* Even */
		*seq = read_seqbegin(lock);
	else			/* Odd */
		read_seqlock_excl_irqsave(lock, flags);

	return flags;
}

/**
 * done_seqretry_irqrestore() - end a seqlock_t lockless reader, or a
 *				non-interruptible locking reader section
 * @lock:  Pointer to &typedef seqlock_t
 * @seq:   Count, from read_seqbegin_or_lock_irqsave()
 * @flags: Caller's saved local interrupt state in case of a locking
 *	   reader, also from read_seqbegin_or_lock_irqsave()
 *
 * This is the ``_irqrestore`` variant of done_seqretry(). The read
 * section must've been opened with read_seqbegin_or_lock_irqsave(), and
 * validated with need_seqretry().
 */
static inline void
done_seqretry_irqrestore(seqlock_t *lock, int seq, unsigned long flags)
{
	if (seq & 1)
		read_sequnlock_excl_irqrestore(lock, flags);
}
#endif /* __LINUX_SEQLOCK_H */
