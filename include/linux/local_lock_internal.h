/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LOCAL_LOCK_H
# error "Do not include directly, include linux/local_lock.h"
#endif

#include <linux/percpu-defs.h>
#include <linux/lockdep.h>

#ifndef CONFIG_PREEMPT_RT

typedef struct {
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map	dep_map;
	struct task_struct	*owner;
#endif
} local_lock_t;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
# define LL_DEP_MAP_INIT(lockname)			\
	.dep_map = {					\
		.name = #lockname,			\
		.wait_type_inner = LD_WAIT_CONFIG,	\
		.lock_type = LD_LOCK_PERCPU,			\
	}
#else
# define LL_DEP_MAP_INIT(lockname)
#endif

#define INIT_LOCAL_LOCK(lockname)	{ LL_DEP_MAP_INIT(lockname) }

#define __local_lock_init(lock)					\
do {								\
	static struct lock_class_key __key;			\
								\
	debug_check_no_locks_freed((void *)lock, sizeof(*lock));\
	lockdep_init_map_type(&(lock)->dep_map, #lock, &__key, 0, \
			      LD_WAIT_CONFIG, LD_WAIT_INV,	\
			      LD_LOCK_PERCPU);			\
} while (0)

#ifdef CONFIG_DEBUG_LOCK_ALLOC
static inline void local_lock_acquire(local_lock_t *l)
{
	lock_map_acquire(&l->dep_map);
	DEBUG_LOCKS_WARN_ON(l->owner);
	l->owner = current;
}

static inline void local_lock_release(local_lock_t *l)
{
	DEBUG_LOCKS_WARN_ON(l->owner != current);
	l->owner = NULL;
	lock_map_release(&l->dep_map);
}

#else /* CONFIG_DEBUG_LOCK_ALLOC */
static inline void local_lock_acquire(local_lock_t *l) { }
static inline void local_lock_release(local_lock_t *l) { }
#endif /* !CONFIG_DEBUG_LOCK_ALLOC */

#define ll_preempt_disable()		preempt_disable()
#define ll_preempt_enable()		preempt_enable()
#define ll_local_irq_disable()		local_irq_disable()
#define ll_local_irq_enable()		local_irq_enable()
#define ll_local_irq_save(flags)	local_irq_save(flags)
#define ll_local_irq_restore(flags)	local_irq_restore(flags)

#else /* !CONFIG_PREEMPT_RT */

/*
 * The preempt RT mapping of local locks: a spinlock.
 */
typedef struct {
	spinlock_t		lock;
} local_lock_t;

#define INIT_LOCAL_LOCK(lockname)	{	\
	__SPIN_LOCK_UNLOCKED((lockname).lock),	\
	}

#define __local_lock_init(l)					\
do {								\
	spin_lock_init(&(l)->lock);				\
} while (0)

static inline void local_lock_acquire(local_lock_t *l)
{
	spin_lock(&l->lock);
}

static inline void local_lock_release(local_lock_t *l)
{
	spin_unlock(&l->lock);
}

/*
 * On RT enabled kernels the serialization is guaranteed by the spinlock in
 * local_lock_t, so the only guarantee to make is to not leave the CPU.
 */
#define ll_preempt_disable()		migrate_disable()
#define ll_preempt_enable()		migrate_enable()
#define ll_local_irq_disable()		migrate_disable()
#define ll_local_irq_enable()		migrate_enable()

#define ll_local_irq_save(flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		flags = 0;				\
		migrate_disable();			\
	} while (0)

#define ll_local_irq_restore(flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		(void)flags;				\
		migrate_enable();			\
	} while (0)

#endif /* CONFIG_PREEMPT_RT */

#define __local_lock(lock)					\
	do {							\
		ll_preempt_disable();				\
		local_lock_acquire(this_cpu_ptr(lock));		\
	} while (0)

#define __local_lock_irq(lock)					\
	do {							\
		ll_local_irq_disable();				\
		local_lock_acquire(this_cpu_ptr(lock));		\
	} while (0)

#define __local_lock_irqsave(lock, flags)			\
	do {							\
		ll_local_irq_save(flags);			\
		local_lock_acquire(this_cpu_ptr(lock));		\
	} while (0)

#define __local_unlock(lock)					\
	do {							\
		local_lock_release(this_cpu_ptr(lock));		\
		ll_preempt_enable();				\
	} while (0)

#define __local_unlock_irq(lock)				\
	do {							\
		local_lock_release(this_cpu_ptr(lock));		\
		ll_local_irq_enable();				\
	} while (0)

#define __local_unlock_irqrestore(lock, flags)			\
	do {							\
		local_lock_release(this_cpu_ptr(lock));		\
		ll_local_irq_restore(flags);			\
	} while (0)
