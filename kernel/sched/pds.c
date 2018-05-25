/*
 *  kernel/sched/pds.c, was kernel/sched.c
 *
 *  PDS-mq Core kernel scheduler code and related syscalls
 *
 *  Copyright (C) 1991-2002  Linus Torvalds
 *
 *  2009-08-13	Brainfuck deadline scheduling policy by Con Kolivas deletes
 *		a whole lot of those previous things.
 *  2017-09-06	Priority and Deadline based Skip list multiple queue kernel
 *		scheduler by Alfred Chen.
 */
#include "pds_sched.h"

#include <linux/sched/rt.h>

#include <linux/context_tracking.h>
#include <linux/compat.h>
#include <linux/blkdev.h>
#include <linux/cpuset.h>
#include <linux/delayacct.h>
#include <linux/freezer.h>
#include <linux/init_task.h>
#include <linux/kprobes.h>
#include <linux/mmu_context.h>
#include <linux/nmi.h>
#include <linux/rcupdate_wait.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/wait_bit.h>

#include <asm/switch_to.h>
#include <asm/tlb.h>

#include "../workqueue_internal.h"
#include "../smpboot.h"

#define CREATE_TRACE_POINTS
#include <trace/events/sched.h>


#define rt_prio(prio)		unlikely((prio) < MAX_RT_PRIO)
#define rt_task(p)		rt_prio((p)->prio)
#define batch_task(p)		(unlikely((p)->policy == SCHED_BATCH))
#define is_rt_policy(policy)	((policy) == SCHED_FIFO || \
					(policy) == SCHED_RR)
#define has_rt_policy(p)	unlikely(is_rt_policy((p)->policy))

/* is_idle_policy() and idleprio_task() are defined in include/linux/sched.h */
#define task_running_idle(p)	unlikely((p)->prio == IDLE_PRIO)

/* is_iso_policy() and iso_task() are defined in include/linux/sched.h */
#define task_running_iso(p)	unlikely((p)->prio == ISO_PRIO)

#define ISO_PERIOD		((5 * HZ) + 1)

#define SCHED_PRIO(p)		((p) + MAX_RT_PRIO)
#define STOP_PRIO		(MAX_RT_PRIO - 1)

/*
 * Some helpers for converting to/from various scales. Use shifts to get
 * approximate multiples of ten for less overhead.
 */
#define JIFFIES_TO_NS(TIME)	((TIME) * (1000000000 / HZ))
#define JIFFY_NS		(1000000000 / HZ)
#define HALF_JIFFY_NS		(1000000000 / HZ / 2)
#define HALF_JIFFY_US		(1000000 / HZ / 2)
#define MS_TO_NS(TIME)		((TIME) << 20)
#define MS_TO_US(TIME)		((TIME) << 10)
#define NS_TO_MS(TIME)		((TIME) >> 20)
#define NS_TO_US(TIME)		((TIME) >> 10)
#define US_TO_NS(TIME)		((TIME) << 10)

#define RESCHED_US	(100) /* Reschedule if less than this many μs left */

#define MIN_VISIBLE_DEADLINE	(1 << 8)

/*
 * BALANCE_INTERVAL should be power of 2 for quick calculation
 */
#define BALANCE_INTERVAL	(MS_TO_NS(32ULL))
#define BALANCE_INTERVAL_MASK	(~(BALANCE_INTERVAL - 1ULL))

enum {
	BASE_CPU_AFFINITY_CHK_LEVEL = 1,
#ifdef CONFIG_SCHED_SMT
	SMT_CPU_AFFINITY_CHK_LEVEL_SPACE_HOLDER,
#endif
#ifdef CONFIG_SCHED_MC
	MC_CPU_AFFINITY_CHK_LEVEL_SPACE_HOLDER,
#endif
	NR_CPU_AFFINITY_CHK_LEVEL
};

static inline void print_scheduler_version(void)
{
	printk(KERN_INFO "pds: PDS-mq CPU Scheduler 0.98q by Alfred Chen.\n");
}

/* task_struct::on_rq states: */
#define TASK_ON_RQ_QUEUED	1
#define TASK_ON_RQ_MIGRATING	2

static inline int task_on_rq_queued(struct task_struct *p)
{
	return p->on_rq == TASK_ON_RQ_QUEUED;
}

static inline int task_on_rq_migrating(struct task_struct *p)
{
	return p->on_rq == TASK_ON_RQ_MIGRATING;
}

/*
 * This is the time all tasks within the same priority round robin.
 * Value is in ms and set to a minimum of 6ms. Scales with number of cpus.
 * Tunable via /proc interface.
 */
#define SCHED_DEFAULT_RR (6)
int rr_interval __read_mostly = SCHED_DEFAULT_RR;

static int __init rr_interval_set(char *str)
{
	u32 rr;

	pr_info("rr_interval: ");
	if (kstrtouint(str, 0, &rr)) {
		pr_cont("using default of %u, unable to parse %s\n",
			rr_interval, str);
		return 1;
	}

	rr_interval = rr;
	pr_cont("%d\n", rr_interval);

	return 1;
}
__setup("rr_interval=", rr_interval_set);


static const u64 sched_prio2deadline[NICE_WIDTH] = {
/* -20 */	  6291456,   6920601,   7612661,   8373927,   9211319,
/* -15 */	 10132450,  11145695,  12260264,  13486290,  14834919,
/* -10 */	 16318410,  17950251,  19745276,  21719803,  23891783,
/*  -5 */	 26280961,  28909057,  31799962,  34979958,  38477953,
/*   0 */	 42325748,  46558322,  51214154,  56335569,  61969125,
/*   5 */	 68166037,  74982640,  82480904,  90728994,  99801893,
/*  10 */	109782082, 120760290, 132836319, 146119950, 160731945,
/*  15 */	176805139, 194485652, 213934217, 235327638, 258860401
};

/*
 * sched_iso_cpu - sysctl which determines the CPUs percentage SCHED_ISO tasks
 * are allowed to run five seconds as real time tasks. This is the total over
 * all online cpus.
 */
int sched_iso_cpu __read_mostly = 70;

/**
 * sched_yield_type - Choose what sort of yield sched_yield will perform.
 * 0: No yield.
 * 1: Yield only to better priority/deadline tasks. (default)
 * 2: Expire timeslice and recalculate deadline.
 */
int sched_yield_type __read_mostly = 1;

/*
 * The quota handed out to tasks of all priority levels when refilling their
 * time_slice.
 */
static inline int timeslice(void)
{
	return MS_TO_US(rr_interval);
}

#ifdef CONFIG_SMP
enum {
SCHED_RQ_EMPTY		=	0,
SCHED_RQ_IDLE,
SCHED_RQ_NORMAL_0,
SCHED_RQ_NORMAL_1,
SCHED_RQ_NORMAL_2,
SCHED_RQ_NORMAL_3,
SCHED_RQ_NORMAL_4,
SCHED_RQ_NORMAL_5,
SCHED_RQ_NORMAL_6,
SCHED_RQ_NORMAL_7,
SCHED_RQ_RT,
NR_SCHED_RQ_QUEUED_LEVEL
};

static cpumask_t sched_rq_queued_masks[NR_SCHED_RQ_QUEUED_LEVEL]
____cacheline_aligned_in_smp;

static DECLARE_BITMAP(sched_rq_queued_masks_bitmap, NR_SCHED_RQ_QUEUED_LEVEL)
____cacheline_aligned_in_smp;

static cpumask_t sched_rq_pending_mask ____cacheline_aligned_in_smp;
static unsigned int sched_nr_rq_pending ____cacheline_aligned_in_smp;

DEFINE_PER_CPU(cpumask_t [NR_CPU_AFFINITY_CHK_LEVEL], sched_cpu_affinity_chk_masks);
DEFINE_PER_CPU(cpumask_t *, sched_cpu_affinity_chk_end_masks);

#ifdef CONFIG_SCHED_SMT
DEFINE_PER_CPU(unsigned int, cpu_has_smt_sibling);

static cpumask_t sched_cpu_sg_idle_mask ____cacheline_aligned_in_smp;
static cpumask_t sched_cpu_sb_suppress_mask ____cacheline_aligned_in_smp;
#endif

static int sched_rq_prio[NR_CPUS] ____cacheline_aligned;

/*
 * Keep a unique ID per domain (we use the first CPUs number in the cpumask of
 * the domain), this allows us to quickly tell if two cpus are in the same cache
 * domain, see cpus_share_cache().
 */
DEFINE_PER_CPU(int, sd_llc_id);

int __weak arch_sd_sibling_asym_packing(void)
{
       return 0*SD_ASYM_PACKING;
}
#else
struct rq *uprq;
#endif /* CONFIG_SMP */

static DEFINE_MUTEX(sched_hotcpu_mutex);

DEFINE_PER_CPU_SHARED_ALIGNED(struct rq, runqueues);

#ifndef prepare_arch_switch
# define prepare_arch_switch(next)	do { } while (0)
#endif
#ifndef finish_arch_post_lock_switch
# define finish_arch_post_lock_switch()	do { } while (0)
#endif

/**
 * A task that is not running or queued will not have a node set.
 * A task that is queued but not running will have a node set.
 * A task that is currently running will have ->on_cpu set but no node set.
 */
static inline bool task_queued(struct task_struct *p)
{
	return !skiplist_empty(&p->sl_node);
}

/*
 * Context: p->pi_lock
 */
static inline struct rq
*__task_access_lock(struct task_struct *p, raw_spinlock_t **plock)
{
	struct rq *rq;
	for (;;) {
		rq = task_rq(p);
		if (p->on_cpu || task_on_rq_queued(p)) {
			raw_spin_lock(&rq->lock);
			if (likely((p->on_cpu || task_on_rq_queued(p))
				   && rq == task_rq(p))) {
				*plock = &rq->lock;
				return rq;
			}
			raw_spin_unlock(&rq->lock);
		} else if (task_on_rq_migrating(p)) {
			do {
				cpu_relax();
			} while (unlikely(task_on_rq_migrating(p)));
		} else {
			*plock = NULL;
			return rq;
		}
	}
}

static inline void
__task_access_unlock(struct task_struct *p, raw_spinlock_t *lock)
{
	if (NULL != lock)
		raw_spin_unlock(lock);
}

struct rq
*task_access_lock_irqsave(struct task_struct *p, raw_spinlock_t **plock,
			  unsigned long *flags)
{
	struct rq *rq;
	for (;;) {
		rq = task_rq(p);
		if (p->on_cpu || task_on_rq_queued(p)) {
			raw_spin_lock_irqsave(&rq->lock, *flags);
			if (likely((p->on_cpu || task_on_rq_queued(p))
				   && rq == task_rq(p))) {
				*plock = &rq->lock;
				return rq;
			}
			raw_spin_unlock_irqrestore(&rq->lock, *flags);
		} else if (task_on_rq_migrating(p)) {
			do {
				cpu_relax();
			} while (unlikely(task_on_rq_migrating(p)));
		} else {
			raw_spin_lock_irqsave(&p->pi_lock, *flags);
			if (likely(!p->on_cpu && !p->on_rq &&
				   rq == task_rq(p))) {
				*plock = &p->pi_lock;
				return rq;
			}
			raw_spin_unlock_irqrestore(&p->pi_lock, *flags);
		}
	}
}

/*
 * RQ-clock updating methods:
 */

static void update_rq_clock_task(struct rq *rq, s64 delta)
{
/*
 * In theory, the compile should just see 0 here, and optimize out the call
 * to sched_rt_avg_update. But I don't trust it...
 */
#ifdef CONFIG_IRQ_TIME_ACCOUNTING
	s64 irq_delta = irq_time_read(cpu_of(rq)) - rq->prev_irq_time;

	/*
	 * Since irq_time is only updated on {soft,}irq_exit, we might run into
	 * this case when a previous update_rq_clock() happened inside a
	 * {soft,}irq region.
	 *
	 * When this happens, we stop ->clock_task and only update the
	 * prev_irq_time stamp to account for the part that fit, so that a next
	 * update will consume the rest. This ensures ->clock_task is
	 * monotonic.
	 *
	 * It does however cause some slight miss-attribution of {soft,}irq
	 * time, a more accurate solution would be to update the irq_time using
	 * the current rq->clock timestamp, except that would require using
	 * atomic ops.
	 */
	if (irq_delta > delta)
		irq_delta = delta;

	rq->prev_irq_time += irq_delta;
	delta -= irq_delta;
#endif
#ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
	if (static_key_false((&paravirt_steal_rq_enabled))) {
		s64 steal = paravirt_steal_clock(cpu_of(rq));

		steal -= rq->prev_steal_time_rq;

		if (unlikely(steal > delta))
			steal = delta;

		rq->prev_steal_time_rq += steal;

		delta -= steal;
	}
#endif

	rq->clock_task += delta;
}

static inline void update_rq_clock(struct rq *rq)
{
	s64 delta = sched_clock_cpu(cpu_of(rq)) - rq->clock;

	if (unlikely(delta <= 0))
		return;
	rq->clock += delta;
	update_rq_clock_task(rq, delta);
}

static inline void update_task_priodl(struct task_struct *p)
{
	p->priodl = (((u64) (p->prio))<<56) | ((p->deadline)>>8);
}

/*
 * Deadline is "now" in niffies + (offset by priority). Setting the deadline
 * is the key to everything. It distributes CPU fairly amongst tasks of the
 * same nice value, it proportions CPU according to nice level, it means the
 * task that last woke up the longest ago has the earliest deadline, thus
 * ensuring that interactive tasks get low latency on wake up. The CPU
 * proportion works out to the square of the virtual deadline difference, so
 * this equation will give nice 19 3% CPU compared to nice 0.
 */
static inline u64 task_deadline_diff(const struct task_struct *p)
{
	return sched_prio2deadline[TASK_USER_PRIO(p)];
}

static inline u64 static_deadline_diff(int static_prio)
{
	return sched_prio2deadline[USER_PRIO(static_prio)];
}

static inline struct task_struct *rq_first_queued_task(struct rq *rq)
{
	struct skiplist_node *node = rq->sl_header.next[0];

	if (node == &rq->sl_header)
		return NULL;

	return skiplist_entry(node, struct task_struct, sl_node);
}

static const int task_dl_hash_tbl[] = {
/*	0           4           8           12           */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1,
/*	16          20          24          28           */
	1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 3, 4, 4, 5, 6, 7
};

static inline int
task_deadline_level(const struct task_struct *p, const struct rq *rq)
{
	u64 delta = (rq->clock + sched_prio2deadline[39] - p->deadline) >> 23;

	delta = min((size_t)delta, ARRAY_SIZE(task_dl_hash_tbl) - 1);
	return task_dl_hash_tbl[delta];
}

#ifdef	CONFIG_SMP
static inline int
task_running_policy_level(const struct task_struct *p, const struct rq *rq)
{
	int prio = p->prio;

	if (NORMAL_PRIO == prio)
		return SCHED_RQ_NORMAL_0 + task_deadline_level(p, rq);

	if (prio <= ISO_PRIO)
		return SCHED_RQ_RT;
	return PRIO_LIMIT - prio;
}

static inline void
__update_sched_rq_queued_masks(struct rq *rq, const int cpu,
			       const int last_level, const int level)
{
	cpumask_clear_cpu(cpu, &sched_rq_queued_masks[last_level]);
	if (cpumask_empty(&sched_rq_queued_masks[last_level]))
		clear_bit(last_level, sched_rq_queued_masks_bitmap);

	cpumask_set_cpu(cpu, &sched_rq_queued_masks[level]);
	set_bit(level, sched_rq_queued_masks_bitmap);

	rq->queued_level = level;
}

static inline void update_sched_rq_queued_masks_normal(struct rq *rq)
{
	struct task_struct *p = rq->curr;

	if (p->prio == NORMAL_PRIO && rq_first_queued_task(rq) == p) {
		int level = task_running_policy_level(p, rq);
		int last_level = rq->queued_level;

		if (last_level == level)
			return;

		__update_sched_rq_queued_masks(rq, cpu_of(rq), last_level, level);
	}
}

static inline void update_sched_rq_queued_masks(struct rq *rq)
{
	int cpu = cpu_of(rq);
	struct task_struct *p;
	int level, last_level = rq->queued_level;

	if ((p = rq_first_queued_task(rq)) == NULL) {
		level = SCHED_RQ_EMPTY;
		sched_rq_prio[cpu] = PRIO_LIMIT;
	} else {
		level = task_running_policy_level(p, rq);
		sched_rq_prio[cpu] = p->prio;
	}

	if (last_level == level)
		return;

	__update_sched_rq_queued_masks(rq, cpu, last_level, level);

#ifdef CONFIG_SCHED_SMT
	if (per_cpu(cpu_has_smt_sibling, cpu)) {
		if (SCHED_RQ_EMPTY == last_level) {
			cpumask_andnot(&sched_cpu_sg_idle_mask,
				       &sched_cpu_sg_idle_mask,
				       cpu_smt_mask(cpu));
		} else if (SCHED_RQ_EMPTY == level) {
			cpumask_t tmp;

			cpumask_and(&tmp, cpu_smt_mask(cpu),
				    &sched_rq_queued_masks[SCHED_RQ_EMPTY]);
			if (cpumask_equal(&tmp, cpu_smt_mask(cpu)))
				cpumask_or(&sched_cpu_sg_idle_mask,
					   &sched_cpu_sg_idle_mask,
					   cpu_smt_mask(cpu));
		}
	}
#endif
}
#else /* CONFIG_SMP */
static inline void update_sched_rq_queued_masks(struct rq *rq) {}
static inline void update_sched_rq_queued_masks_normal(struct rq *rq) {}
#endif

#ifdef CONFIG_NO_HZ_FULL
/*
 * Tick may be needed by tasks in the runqueue depending on their policy and
 * requirements. If tick is needed, lets send the target an IPI to kick it out
 * of nohz mode if necessary.
 */
static inline void sched_update_tick_dependency(struct rq *rq)
{
	int cpu;

	if (!tick_nohz_full_enabled())
		return;

	cpu = cpu_of(rq);

	if (!tick_nohz_full_cpu(cpu))
		return;

	if (rq->nr_running < 2)
		tick_nohz_dep_clear_cpu(cpu, TICK_DEP_BIT_SCHED);
	else
		tick_nohz_dep_set_cpu(cpu, TICK_DEP_BIT_SCHED);
}
#else /* !CONFIG_NO_HZ_FULL */
static inline void sched_update_tick_dependency(struct rq *rq) { }
#endif

/*
 * Removing from the runqueue. Deleting a task from the skip list is done
 * via the stored node reference in the task struct and does not require a full
 * look up. Thus it occurs in O(k) time where k is the "level" of the list the
 * task was stored at - usually < 4, max 16.
 *
 * Context: rq->lock
 */
static inline void dequeue_task(struct task_struct *p, struct rq *rq)
{
	lockdep_assert_held(&rq->lock);

	WARN_ONCE(task_rq(p) != rq, "pds: dequeue task reside on cpu%d from cpu%d\n",
		  task_cpu(p), cpu_of(rq));
	if (skiplist_del_init(&rq->sl_header, &p->sl_node))
		update_sched_rq_queued_masks(rq);
	rq->nr_running--;
#ifdef CONFIG_SMP
	if (1 == rq->nr_running) {
		cpumask_clear_cpu(cpu_of(rq), &sched_rq_pending_mask);
		sched_nr_rq_pending = cpumask_weight(&sched_rq_pending_mask);
	}
#endif

	sched_update_tick_dependency(rq);

	sched_info_dequeued(rq, p);
}

/*
 * To determine if it's safe for a task of SCHED_IDLE to actually run as
 * an idle task, we ensure none of the following conditions are met.
 */
static bool idleprio_suitable(struct task_struct *p)
{
	return (!freezing(p) && !signal_pending(p) &&
		!(task_contributes_to_load(p)) && !(p->flags & (PF_EXITING)));
}

/*
 * To determine if a task of SCHED_ISO can run in pseudo-realtime, we check
 * that the iso_refractory flag is not set.
 */
static bool isoprio_suitable(struct rq *rq)
{
	return !rq->iso_refractory;
}

/*
 * pds_skiplist_random_level -- Returns a pseudo-random level number for skip
 * list node which is used in PDS run queue.
 *
 * In current implementation, based on testing, the first 8 bits in microseconds
 * of niffies are suitable for random level population.
 * find_first_bit() is used to satisfy p = 0.5 between each levels, and there
 * should be platform hardware supported instruction(known as ctz/clz) to speed
 * up this function.
 * The skiplist level for a task is populated when task is created and doesn't
 * change in task's life time. When task is being inserted into run queue, this
 * skiplist level is set to task's sl_node->level, the skiplist insert function
 * may change it based on current level of the skip lsit.
 */
static inline int pds_skiplist_random_level(const struct task_struct *p)
{
	long unsigned int randseed;

	/*
	 * 1. Some architectures don't have better than microsecond resolution
	 * so mask out ~microseconds as a factor of the random seed for skiplist
	 * insertion.
	 * 2. Use address of task structure pointer as another factor of the
	 * random seed for task burst forking scenario. Shift right 9 bits to
	 * remove the aligned zero bits in the task structure address.
	 */
	randseed = (task_rq(p)->clock >> 10) ^ ((long unsigned int)p >> 9);

	return find_first_bit(&randseed, NUM_SKIPLIST_LEVEL - 1);
}

/**
 * pds_skiplist_task_search -- search function used in PDS run queue skip list
 * node insert operation.
 * @it: iterator pointer to the node in the skip list
 * @node: pointer to the skiplist_node to be inserted
 *
 * Returns true if key of @it is less or equal to key value of @node, otherwise
 * false.
 */
static inline bool
pds_skiplist_task_search(struct skiplist_node *it, struct skiplist_node *node)
{
	return (skiplist_entry(it, struct task_struct, sl_node)->priodl <=
		skiplist_entry(node, struct task_struct, sl_node)->priodl);
}

/*
 * Define the skip list insert function for PDS
 */
DEFINE_SKIPLIST_INSERT_FUNC(pds_skiplist_insert, pds_skiplist_task_search);

/*
 * Adding task to the runqueue.
 *
 * Context: rq->lock
 */
static inline void enqueue_task(struct task_struct *p, struct rq *rq)
{
	lockdep_assert_held(&rq->lock);

	/* Check ISO tasks suitable to run normal priority */
	if (iso_task(p)) {
		p->prio = isoprio_suitable(rq)? p->normal_prio:NORMAL_PRIO;
		update_task_priodl(p);
	}

	WARN_ONCE(task_rq(p) != rq, "pds: enqueue task reside on cpu%d to cpu%d\n",
		  task_cpu(p), cpu_of(rq));

	p->sl_node.level = p->sl_level;
	if (pds_skiplist_insert(&rq->sl_header, &p->sl_node))
		update_sched_rq_queued_masks(rq);
	rq->nr_running++;
#ifdef CONFIG_SMP
	if (2 == rq->nr_running) {
		cpumask_set_cpu(cpu_of(rq), &sched_rq_pending_mask);
		sched_nr_rq_pending = cpumask_weight(&sched_rq_pending_mask);
	}
#endif

	sched_update_tick_dependency(rq);

	sched_info_queued(rq, p);

	/*
	 * If in_iowait is set, the code below may not trigger any cpufreq
	 * utilization updates, so do it here explicitly with the IOWAIT flag
	 * passed.
	 */
	if (p->in_iowait)
		cpufreq_update_this_cpu(rq, SCHED_CPUFREQ_IOWAIT);
}

static inline void requeue_task(struct task_struct *p, struct rq *rq)
{
	bool b_first;

	lockdep_assert_held(&rq->lock);

	WARN_ONCE(task_rq(p) != rq, "pds: cpu[%d] requeue task reside on cpu%d\n",
		  cpu_of(rq), task_cpu(p));

	b_first = skiplist_del_init(&rq->sl_header, &p->sl_node);

	p->sl_node.level = p->sl_level;
	if (pds_skiplist_insert(&rq->sl_header, &p->sl_node) || b_first)
		update_sched_rq_queued_masks(rq);
}

/*
 * cmpxchg based fetch_or, macro so it works for different integer types
 */
#define fetch_or(ptr, mask)						\
	({								\
		typeof(ptr) _ptr = (ptr);				\
		typeof(mask) _mask = (mask);				\
		typeof(*_ptr) _old, _val = *_ptr;			\
									\
		for (;;) {						\
			_old = cmpxchg(_ptr, _val, _val | _mask);	\
			if (_old == _val)				\
				break;					\
			_val = _old;					\
		}							\
	_old;								\
})

#if defined(CONFIG_SMP) && defined(TIF_POLLING_NRFLAG)
/*
 * Atomically set TIF_NEED_RESCHED and test for TIF_POLLING_NRFLAG,
 * this avoids any races wrt polling state changes and thereby avoids
 * spurious IPIs.
 */
static bool set_nr_and_not_polling(struct task_struct *p)
{
	struct thread_info *ti = task_thread_info(p);
	return !(fetch_or(&ti->flags, _TIF_NEED_RESCHED) & _TIF_POLLING_NRFLAG);
}

/*
 * Atomically set TIF_NEED_RESCHED if TIF_POLLING_NRFLAG is set.
 *
 * If this returns true, then the idle task promises to call
 * sched_ttwu_pending() and reschedule soon.
 */
static bool set_nr_if_polling(struct task_struct *p)
{
	struct thread_info *ti = task_thread_info(p);
	typeof(ti->flags) old, val = READ_ONCE(ti->flags);

	for (;;) {
		if (!(val & _TIF_POLLING_NRFLAG))
			return false;
		if (val & _TIF_NEED_RESCHED)
			return true;
		old = cmpxchg(&ti->flags, val, val | _TIF_NEED_RESCHED);
		if (old == val)
			break;
		val = old;
	}
	return true;
}

#else
static bool set_nr_and_not_polling(struct task_struct *p)
{
	set_tsk_need_resched(p);
	return true;
}

#ifdef CONFIG_SMP
static bool set_nr_if_polling(struct task_struct *p)
{
	return false;
}
#endif
#endif

/*
 * resched_curr - mark rq's current task 'to be rescheduled now'.
 *
 * On UP this means the setting of the need_resched flag, on SMP it
 * might also involve a cross-CPU call to trigger the scheduler on
 * the target CPU.
 */
void resched_curr(struct rq *rq)
{
	struct task_struct *curr = rq->curr;
	int cpu;

	lockdep_assert_held(&rq->lock);

	if (test_tsk_need_resched(curr))
		return;

	cpu = cpu_of(rq);
	if (cpu == smp_processor_id()) {
		set_tsk_need_resched(curr);
		set_preempt_need_resched();
		return;
	}

	if (set_nr_and_not_polling(curr))
		smp_send_reschedule(cpu);
	else
		trace_sched_wake_idle_without_ipi(cpu);
}

static inline void check_preempt_curr(struct rq *rq, struct task_struct *p)
{
	if (p->priodl < rq->curr->priodl)
		resched_curr(rq);
}

#ifdef CONFIG_SCHED_HRTICK
/*
 * Use HR-timers to deliver accurate preemption points.
 */

static void hrtick_clear(struct rq *rq)
{
	if (hrtimer_active(&rq->hrtick_timer))
		hrtimer_cancel(&rq->hrtick_timer);
}

/*
 * High-resolution timer tick.
 * Runs from hardirq context with interrupts disabled.
 */
static enum hrtimer_restart hrtick(struct hrtimer *timer)
{
	struct rq *rq = container_of(timer, struct rq, hrtick_timer);
	struct task_struct *p;

	WARN_ON_ONCE(cpu_of(rq) != smp_processor_id());

	raw_spin_lock(&rq->lock);
	p = rq->curr;
	p->time_slice = 0;
	resched_curr(rq);
	raw_spin_unlock(&rq->lock);

	return HRTIMER_NORESTART;
}

/*
 * Use hrtick when:
 *  - enabled by features
 *  - hrtimer is actually high res
 */
static inline int hrtick_enabled(struct rq *rq)
{
	/**
	 * PDS doesn't support sched_feat yet
	if (!sched_feat(HRTICK))
		return 0;
	*/
	if (!cpu_active(cpu_of(rq)))
		return 0;
	return hrtimer_is_hres_active(&rq->hrtick_timer);
}

#ifdef CONFIG_SMP

static void __hrtick_restart(struct rq *rq)
{
	struct hrtimer *timer = &rq->hrtick_timer;

	hrtimer_start_expires(timer, HRTIMER_MODE_ABS_PINNED);
}

/*
 * called from hardirq (IPI) context
 */
static void __hrtick_start(void *arg)
{
	struct rq *rq = arg;

	raw_spin_lock(&rq->lock);
	__hrtick_restart(rq);
	rq->hrtick_csd_pending = 0;
	raw_spin_unlock(&rq->lock);
}

/*
 * Called to set the hrtick timer state.
 *
 * called with rq->lock held and irqs disabled
 */
void hrtick_start(struct rq *rq, u64 delay)
{
	struct hrtimer *timer = &rq->hrtick_timer;
	ktime_t time;
	s64 delta;

	/*
	 * Don't schedule slices shorter than 10000ns, that just
	 * doesn't make sense and can cause timer DoS.
	 */
	delta = max_t(s64, delay, 10000LL);
	time = ktime_add_ns(timer->base->get_time(), delta);

	hrtimer_set_expires(timer, time);

	if (rq == this_rq()) {
		__hrtick_restart(rq);
	} else if (!rq->hrtick_csd_pending) {
		smp_call_function_single_async(cpu_of(rq), &rq->hrtick_csd);
		rq->hrtick_csd_pending = 1;
	}
}

#else
/*
 * Called to set the hrtick timer state.
 *
 * called with rq->lock held and irqs disabled
 */
void hrtick_start(struct rq *rq, u64 delay)
{
	/*
	 * Don't schedule slices shorter than 10000ns, that just
	 * doesn't make sense. Rely on vruntime for fairness.
	 */
	delay = max_t(u64, delay, 10000LL);
	hrtimer_start(&rq->hrtick_timer, ns_to_ktime(delay),
		      HRTIMER_MODE_REL_PINNED);
}
#endif /* CONFIG_SMP */

static void hrtick_rq_init(struct rq *rq)
{
#ifdef CONFIG_SMP
	rq->hrtick_csd_pending = 0;

	rq->hrtick_csd.flags = 0;
	rq->hrtick_csd.func = __hrtick_start;
	rq->hrtick_csd.info = rq;
#endif

	hrtimer_init(&rq->hrtick_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	rq->hrtick_timer.function = hrtick;
}

static inline int rq_dither(struct rq *rq)
{
	if ((rq->clock - rq->last_tick > HALF_JIFFY_NS) || hrtick_enabled(rq))
		return 0;

	return HALF_JIFFY_NS;
}

#else	/* CONFIG_SCHED_HRTICK */
static inline int hrtick_enabled(struct rq *rq)
{
	return 0;
}

static inline void hrtick_clear(struct rq *rq)
{
}

static inline void hrtick_rq_init(struct rq *rq)
{
}

static inline int rq_dither(struct rq *rq)
{
	return (rq->clock - rq->last_tick > HALF_JIFFY_NS)? 0:HALF_JIFFY_NS;
}
#endif	/* CONFIG_SCHED_HRTICK */

static inline int normal_prio(struct task_struct *p)
{
	if (has_rt_policy(p))
		return MAX_RT_PRIO - 1 - p->rt_priority;
	if (idleprio_task(p))
		return IDLE_PRIO;
	if (iso_task(p))
		return ISO_PRIO;
	return NORMAL_PRIO;
}

/*
 * Calculate the current priority, i.e. the priority
 * taken into account by the scheduler. This value might
 * be boosted by RT tasks as it will be RT if the task got
 * RT-boosted. If not then it returns p->normal_prio.
 */
static int effective_prio(struct task_struct *p)
{
	p->normal_prio = normal_prio(p);
	/*
	 * If we are RT tasks or we were boosted to RT priority,
	 * keep the priority unchanged. Otherwise, update priority
	 * to the normal priority:
	 */
	if (!rt_prio(p->prio))
		return p->normal_prio;
	return p->prio;
}

/*
 * activate_task - move a task to the runqueue.
 *
 * Context: rq->lock
 */
static void activate_task(struct task_struct *p, struct rq *rq)
{
	if (task_contributes_to_load(p))
		rq->nr_uninterruptible--;
	enqueue_task(p, rq);
	p->on_rq = 1;
	cpufreq_update_this_cpu(rq, 0);
}

/*
 * deactivate_task - If it's running, it's not on the rq and we can just
 * decrement the nr_running.
 *
 * Context: rq->lock
 */
static inline void deactivate_task(struct task_struct *p, struct rq *rq)
{
	if (task_contributes_to_load(p))
		rq->nr_uninterruptible++;
	dequeue_task(p, rq);
	p->on_rq = 0;
	cpufreq_update_this_cpu(rq, 0);
}

static inline void __set_task_cpu(struct task_struct *p, unsigned int cpu)
{
#ifdef CONFIG_SMP
	/*
	 * After ->cpu is set up to a new value, task_access_lock(p, ...) can be
	 * successfully executed on another CPU. We must ensure that updates of
	 * per-task data have been completed by this moment.
	 */
	smp_wmb();

#ifdef CONFIG_THREAD_INFO_IN_TASK
	p->cpu = cpu;
#else
	task_thread_info(p)->cpu = cpu;
#endif
#endif
}

#ifdef CONFIG_SMP
void set_task_cpu(struct task_struct *p, unsigned int new_cpu)
{
#ifdef CONFIG_SCHED_DEBUG
	/*
	 * We should never call set_task_cpu() on a blocked task,
	 * ttwu() will sort out the placement.
	 */
	WARN_ON_ONCE(p->state != TASK_RUNNING && p->state != TASK_WAKING &&
		     !p->on_rq);
#ifdef CONFIG_LOCKDEP
	/*
	 * The caller should hold either p->pi_lock or rq->lock, when changing
	 * a task's CPU. ->pi_lock for waking tasks, rq->lock for runnable tasks.
	 *
	 * sched_move_task() holds both and thus holding either pins the cgroup,
	 * see task_group().
	 */
	WARN_ON_ONCE(debug_locks && !(lockdep_is_held(&p->pi_lock) ||
				      lockdep_is_held(&task_rq(p)->lock)));
#endif
	/*
	 * Clearly, migrating tasks to offline CPUs is a fairly daft thing.
	 */
	WARN_ON_ONCE(!cpu_online(new_cpu));
#endif
	if (task_cpu(p) == new_cpu)
		return;
	trace_sched_migrate_task(p, new_cpu);
	perf_event_task_migrate(p);

	__set_task_cpu(p, new_cpu);
}

/*
 * This is how migration works:
 *
 * 1) we invoke migration_cpu_stop() on the target CPU using
 *    stop_one_cpu().
 * 2) stopper starts to run (implicitly forcing the migrated thread
 *    off the CPU)
 * 3) it checks whether the migrated task is still in the wrong runqueue.
 * 4) if it's in the wrong runqueue then the migration thread removes
 *    it and puts it into the right queue.
 * 5) stopper completes and stop_one_cpu() returns and the migration
 *    is done.
 */

/*
 * detach_task() -- detach the task for the migration specified in @target_cpu
 */
static void detach_task(struct rq *rq, struct task_struct *p, int target_cpu)
{
	lockdep_assert_held(&rq->lock);

	p->on_rq = TASK_ON_RQ_MIGRATING;
	if (task_contributes_to_load(p))
		rq->nr_uninterruptible++;
	dequeue_task(p, rq);

	set_task_cpu(p, target_cpu);
}

/*
 * attach_task() -- attach the task detached by detach_task() to its new rq.
 */
static void attach_task(struct rq *rq, struct task_struct *p)
{
	lockdep_assert_held(&rq->lock);

	BUG_ON(task_rq(p) != rq);

	if (task_contributes_to_load(p))
		rq->nr_uninterruptible--;
	enqueue_task(p, rq);
	p->on_rq = TASK_ON_RQ_QUEUED;
	cpufreq_update_this_cpu(rq, 0);

	check_preempt_curr(rq, p);
}

/*
 * move_queued_task - move a queued task to new rq.
 *
 * Returns (locked) new rq. Old rq's lock is released.
 */
static struct rq *move_queued_task(struct rq *rq, struct task_struct *p, int
				   new_cpu)
{
	detach_task(rq, p, new_cpu);
	raw_spin_unlock(&rq->lock);

	rq = cpu_rq(new_cpu);

	raw_spin_lock(&rq->lock);
	update_rq_clock(rq);

	attach_task(rq, p);

	return rq;
}

struct migration_arg {
	struct task_struct *task;
	int dest_cpu;
};

/*
 * Move (not current) task off this CPU, onto the destination CPU. We're doing
 * this because either it can't run here any more (set_cpus_allowed()
 * away from this CPU, or CPU going down), or because we're
 * attempting to rebalance this task on exec (sched_exec).
 *
 * So we race with normal scheduler movements, but that's OK, as long
 * as the task is no longer on this CPU.
 */
static struct rq *__migrate_task(struct rq *rq, struct task_struct *p, int
				 dest_cpu)
{
	if (p->flags & PF_KTHREAD) {
		if (unlikely(!cpu_online(dest_cpu)))
			return rq;
	} else {
		if (unlikely(!cpu_active(dest_cpu)))
			return rq;
	}

	/* Affinity changed (again). */
	if (unlikely(!cpumask_test_cpu(dest_cpu, &p->cpus_allowed)))
		return rq;

	update_rq_clock(rq);
	return move_queued_task(rq, p, dest_cpu);
}

/*
 * migration_cpu_stop - this will be executed by a highprio stopper thread
 * and performs thread migration by bumping thread off CPU then
 * 'pushing' onto another runqueue.
 */
static int migration_cpu_stop(void *data)
{
	struct migration_arg *arg = data;
	struct task_struct *p = arg->task;
	struct rq *rq = this_rq();

	/*
	 * The original target CPU might have gone down and we might
	 * be on another CPU but it doesn't matter.
	 */
	local_irq_disable();

	raw_spin_lock(&p->pi_lock);
	raw_spin_lock(&rq->lock);
	/*
	 * If task_rq(p) != rq, it cannot be migrated here, because we're
	 * holding rq->lock, if p->on_rq == 0 it cannot get enqueued because
	 * we're holding p->pi_lock.
	 */
	if (task_rq(p) == rq)
		if (task_on_rq_queued(p))
			rq = __migrate_task(rq, p, arg->dest_cpu);
	raw_spin_unlock(&rq->lock);
	raw_spin_unlock(&p->pi_lock);

	local_irq_enable();
	return 0;
}

static inline void
set_cpus_allowed_common(struct task_struct *p, const struct cpumask *new_mask)
{
	cpumask_copy(&p->cpus_allowed, new_mask);
	p->nr_cpus_allowed = cpumask_weight(new_mask);
}

void do_set_cpus_allowed(struct task_struct *p, const struct cpumask *new_mask)
{
	set_cpus_allowed_common(p, new_mask);
}
#endif

/* Enter with rq lock held. We know p is on the local CPU */
static inline void __set_tsk_resched(struct task_struct *p)
{
	set_tsk_need_resched(p);
	set_preempt_need_resched();
}

/**
 * task_curr - is this task currently executing on a CPU?
 * @p: the task in question.
 *
 * Return: 1 if the task is currently executing. 0 otherwise.
 */
inline int task_curr(const struct task_struct *p)
{
	return cpu_curr(task_cpu(p)) == p;
}

#ifdef CONFIG_SMP
/*
 * wait_task_inactive - wait for a thread to unschedule.
 *
 * If @match_state is nonzero, it's the @p->state value just checked and
 * not expected to change.  If it changes, i.e. @p might have woken up,
 * then return zero.  When we succeed in waiting for @p to be off its CPU,
 * we return a positive number (its total switch count).  If a second call
 * a short while later returns the same number, the caller can be sure that
 * @p has remained unscheduled the whole time.
 *
 * The caller must ensure that the task *will* unschedule sometime soon,
 * else this function might spin for a *long* time. This function can't
 * be called with interrupts off, or it may introduce deadlock with
 * smp_call_function() if an IPI is sent by the same process we are
 * waiting to become inactive.
 */
unsigned long wait_task_inactive(struct task_struct *p, long match_state)
{
	unsigned long flags;
	bool running, on_rq;
	unsigned long ncsw;
	struct rq *rq;
	raw_spinlock_t *lock;

	for (;;) {
		rq = task_rq(p);

		/*
		 * If the task is actively running on another CPU
		 * still, just relax and busy-wait without holding
		 * any locks.
		 *
		 * NOTE! Since we don't hold any locks, it's not
		 * even sure that "rq" stays as the right runqueue!
		 * But we don't care, since this will return false
		 * if the runqueue has changed and p is actually now
		 * running somewhere else!
		 */
		while (task_running(p) && p == rq->curr) {
			if (match_state && unlikely(p->state != match_state))
				return 0;
			cpu_relax();
		}

		/*
		 * Ok, time to look more closely! We need the rq
		 * lock now, to be *sure*. If we're wrong, we'll
		 * just go back and repeat.
		 */
		task_access_lock_irqsave(p, &lock, &flags);
		trace_sched_wait_task(p);
		running = task_running(p);
		on_rq = p->on_rq;
		ncsw = 0;
		if (!match_state || p->state == match_state)
			ncsw = p->nvcsw | LONG_MIN; /* sets MSB */
		task_access_unlock_irqrestore(p, lock, &flags);

		/*
		 * If it changed from the expected state, bail out now.
		 */
		if (unlikely(!ncsw))
			break;

		/*
		 * Was it really running after all now that we
		 * checked with the proper locks actually held?
		 *
		 * Oops. Go back and try again..
		 */
		if (unlikely(running)) {
			cpu_relax();
			continue;
		}

		/*
		 * It's not enough that it's not actively running,
		 * it must be off the runqueue _entirely_, and not
		 * preempted!
		 *
		 * So if it was still runnable (but just not actively
		 * running right now), it's preempted, and we should
		 * yield - it could be a while.
		 */
		if (unlikely(on_rq)) {
			ktime_t to = NSEC_PER_SEC / HZ;

			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_hrtimeout(&to, HRTIMER_MODE_REL);
			continue;
		}

		/*
		 * Ahh, all good. It wasn't running, and it wasn't
		 * runnable, which means that it will never become
		 * running in the future either. We're all done!
		 */
		break;
	}

	return ncsw;
}

/***
 * kick_process - kick a running thread to enter/exit the kernel
 * @p: the to-be-kicked thread
 *
 * Cause a process which is running on another CPU to enter
 * kernel-mode, without any delay. (to get signals handled.)
 *
 * NOTE: this function doesn't have to take the runqueue lock,
 * because all it wants to ensure is that the remote task enters
 * the kernel. If the IPI races and the task has been migrated
 * to another CPU then no harm is done and the purpose has been
 * achieved as well.
 */
void kick_process(struct task_struct *p)
{
	int cpu;

	preempt_disable();
	cpu = task_cpu(p);
	if ((cpu != smp_processor_id()) && task_curr(p))
		smp_send_reschedule(cpu);
	preempt_enable();
}
EXPORT_SYMBOL_GPL(kick_process);

/*
 * ->cpus_allowed is protected by both rq->lock and p->pi_lock
 *
 * A few notes on cpu_active vs cpu_online:
 *
 *  - cpu_active must be a subset of cpu_online
 *
 *  - on CPU-up we allow per-CPU kthreads on the online && !active CPU,
 *    see __set_cpus_allowed_ptr(). At this point the newly online
 *    CPU isn't yet part of the sched domains, and balancing will not
 *    see it.
 *
 *  - on cpu-down we clear cpu_active() to mask the sched domains and
 *    avoid the load balancer to place new tasks on the to be removed
 *    CPU. Existing tasks will remain running there and will be taken
 *    off.
 *
 * This means that fallback selection must not select !active CPUs.
 * And can assume that any active CPU must be online. Conversely
 * select_task_rq() below may allow selection of !active CPUs in order
 * to satisfy the above rules.
 */
static int select_fallback_rq(int cpu, struct task_struct *p)
{
	int nid = cpu_to_node(cpu);
	const struct cpumask *nodemask = NULL;
	enum { cpuset, possible, fail } state = cpuset;
	int dest_cpu;

	/*
	 * If the node that the CPU is on has been offlined, cpu_to_node()
	 * will return -1. There is no CPU on the node, and we should
	 * select the CPU on the other node.
	 */
	if (nid != -1) {
		nodemask = cpumask_of_node(nid);

		/* Look for allowed, online CPU in same node. */
		for_each_cpu(dest_cpu, nodemask) {
			if (!cpu_active(dest_cpu))
				continue;
			if (cpumask_test_cpu(dest_cpu, &p->cpus_allowed))
				return dest_cpu;
		}
	}

	for (;;) {
		/* Any allowed, online CPU? */
		for_each_cpu(dest_cpu, &p->cpus_allowed) {
			if (!(p->flags & PF_KTHREAD) && !cpu_active(dest_cpu))
				continue;
			if (!cpu_online(dest_cpu))
				continue;
			goto out;
		}

		/* No more Mr. Nice Guy. */
		switch (state) {
		case cpuset:
			if (IS_ENABLED(CONFIG_CPUSETS)) {
				cpuset_cpus_allowed_fallback(p);
				state = possible;
				break;
			}
			/* Fall-through */
		case possible:
			do_set_cpus_allowed(p, cpu_possible_mask);
			state = fail;
			break;

		case fail:
			BUG();
			break;
		}
	}

out:
	if (state != cpuset) {
		/*
		 * Don't tell them about moving exiting tasks or
		 * kernel threads (both mm NULL), since they never
		 * leave kernel.
		 */
		if (p->mm && printk_ratelimit()) {
			printk_deferred("process %d (%s) no longer affine to cpu%d\n",
					task_pid_nr(p), p->comm, cpu);
		}
	}

	return dest_cpu;
}

static inline int best_mask_cpu(const int cpu, cpumask_t *cpumask)
{
	cpumask_t tmp, *mask;

	if (cpumask_weight(cpumask) == 1)
		return cpumask_first(cpumask);

	if (cpumask_test_cpu(cpu, cpumask))
		return cpu;

	for (mask = &(per_cpu(sched_cpu_affinity_chk_masks, cpu)[0]);
	     mask < per_cpu(sched_cpu_affinity_chk_end_masks, cpu); mask++)
		if (cpumask_and(&tmp, cpumask, mask))
			return cpumask_any(&tmp);

	/* Safe fallback, should never come here */
	return cpumask_first(cpumask);
}

/*
 * task_preemptible_rq - return the rq which the given task can preempt on
 * @p: task wants to preempt CPU
 * @only_preempt_low_policy: indicate only preempt rq running low policy than @p
 */
static inline int
task_preemptible_rq(struct task_struct *p, cpumask_t *chk_mask,
		    int only_preempt_low_policy)
{
	cpumask_t tmp;
	int level, preempt_level;

	preempt_level = task_running_policy_level(p, this_rq());
	level = find_first_bit(sched_rq_queued_masks_bitmap,
			       NR_SCHED_RQ_QUEUED_LEVEL);

#ifdef CONFIG_SCHED_SMT
	if (SCHED_RQ_EMPTY == level) {
		if(cpumask_and(&tmp, chk_mask, &sched_rq_queued_masks[level])) {
			cpumask_t smt_tmp;

			if (cpumask_and(&smt_tmp, &tmp, &sched_cpu_sg_idle_mask))
				return best_mask_cpu(task_cpu(p), &smt_tmp);
			return best_mask_cpu(task_cpu(p), &tmp);
		}
		level = find_next_bit(sched_rq_queued_masks_bitmap,
				      NR_SCHED_RQ_QUEUED_LEVEL,
				      level + 1);
	}
#endif

	while (level < preempt_level) {
		if(cpumask_and(&tmp, chk_mask, &sched_rq_queued_masks[level]))
			return best_mask_cpu(task_cpu(p), &tmp);

		level = find_next_bit(sched_rq_queued_masks_bitmap,
				      NR_SCHED_RQ_QUEUED_LEVEL,
				      level + 1);
	}

	/*
	 * only_preempt_low_policy indicate just preempt rq running lower
	 * policy task than p
	 */
	if (only_preempt_low_policy)
		return best_mask_cpu(task_cpu(p), chk_mask);

	if (unlikely(level != preempt_level))
		return best_mask_cpu(task_cpu(p), chk_mask);

	/* IDLEPRIO tasks never preempt anything but idle */
	if (idleprio_task(p))
		return best_mask_cpu(task_cpu(p), chk_mask);

	if (cpumask_and(&tmp, chk_mask, &sched_rq_queued_masks[preempt_level])) {
		if (unlikely((SCHED_RQ_RT == level))) {
			unsigned int cpu;

			for_each_cpu (cpu, &tmp)
				if (p->prio < sched_rq_prio[cpu])
					return cpu;
		}
		return best_mask_cpu(task_cpu(p), &tmp);
	}

	return best_mask_cpu(task_cpu(p), chk_mask);
}

/*
 * wake flags
 */
#define WF_SYNC		0x01		/* waker goes to sleep after wakeup */
#define WF_FORK		0x02		/* child wakeup after fork */
#define WF_MIGRATED	0x04		/* internal use, task got migrated */

static inline int select_task_rq(struct task_struct *p, int wake_flags)
{
	cpumask_t chk_mask;

	if (unlikely(!cpumask_and(&chk_mask, &p->cpus_allowed, cpu_online_mask)))
		return select_fallback_rq(task_cpu(p), p);

	/*
	 * Sync wakeups (i.e. those types of wakeups where the waker
	 * has indicated that it will leave the CPU in short order)
	 * don't trigger a preemption if there are no idle cpus,
	 * instead waiting for current to deschedule.
	 */
	return task_preemptible_rq(p, &chk_mask, wake_flags & WF_SYNC);
}
#else /* CONFIG_SMP */
static inline int select_task_rq(struct task_struct *p, int wake_flags)
{
	return 0;
}
#endif /* CONFIG_SMP */

static void
ttwu_stat(struct task_struct *p, int cpu, int wake_flags)
{
	struct rq *rq;

	if (!schedstat_enabled())
		return;

	rq= this_rq();

#ifdef CONFIG_SMP
	if (cpu == rq->cpu)
		__schedstat_inc(rq->ttwu_local);
	else {
		/** PDS ToDo:
		 * How to do ttwu_wake_remote
		 */
	}
#endif /* CONFIG_SMP */

	__schedstat_inc(rq->ttwu_count);
}

static inline void ttwu_activate(struct task_struct *p, struct rq *rq)
{
	activate_task(p, rq);

	/*
	 * if a worker is waking up, notify workqueue. Note that on PDS, we
	 * don't really know what CPU it will be, so we fake it for
	 * wq_worker_waking_up :/
	 */
	if (p->flags & PF_WQ_WORKER)
		wq_worker_waking_up(p, cpu_of(rq));
}

/*
 * Mark the task runnable and perform wakeup-preemption.
 */
static inline void
ttwu_do_wakeup(struct rq *rq, struct task_struct *p, int wake_flags)
{
	p->state = TASK_RUNNING;
	trace_sched_wakeup(p);
}

static inline void
ttwu_do_activate(struct rq *rq, struct task_struct *p, int wake_flags)
{
#ifdef CONFIG_SMP
	if (p->sched_contributes_to_load)
		rq->nr_uninterruptible--;
#endif

	ttwu_activate(p, rq);
	ttwu_do_wakeup(rq, p, 0);
}

static int ttwu_remote(struct task_struct *p, int wake_flags)
{
	struct rq *rq;
	raw_spinlock_t *lock;
	int ret = 0;

	rq = __task_access_lock(p, &lock);
	/*
	if (task_running(p) || task_queued(p)) {
	*/
	if (task_on_rq_queued(p)) {
		ttwu_do_wakeup(rq, p, wake_flags);
		ret = 1;
	}
	__task_access_unlock(p, lock);

	return ret;
}

/*
 * Notes on Program-Order guarantees on SMP systems.
 *
 *  MIGRATION
 *
 * The basic program-order guarantee on SMP systems is that when a task [t]
 * migrates, all its activity on its old CPU [c0] happens-before any subsequent
 * execution on its new CPU [c1].
 *
 * For migration (of runnable tasks) this is provided by the following means:
 *
 *  A) UNLOCK of the rq(c0)->lock scheduling out task t
 *  B) migration for t is required to synchronize *both* rq(c0)->lock and
 *     rq(c1)->lock (if not at the same time, then in that order).
 *  C) LOCK of the rq(c1)->lock scheduling in task
 *
 * Transitivity guarantees that B happens after A and C after B.
 * Note: we only require RCpc transitivity.
 * Note: the CPU doing B need not be c0 or c1
 *
 * Example:
 *
 *   CPU0            CPU1            CPU2
 *
 *   LOCK rq(0)->lock
 *   sched-out X
 *   sched-in Y
 *   UNLOCK rq(0)->lock
 *
 *                                   LOCK rq(0)->lock // orders against CPU0
 *                                   dequeue X
 *                                   UNLOCK rq(0)->lock
 *
 *                                   LOCK rq(1)->lock
 *                                   enqueue X
 *                                   UNLOCK rq(1)->lock
 *
 *                   LOCK rq(1)->lock // orders against CPU2
 *                   sched-out Z
 *                   sched-in X
 *                   UNLOCK rq(1)->lock
 *
 *
 *  BLOCKING -- aka. SLEEP + WAKEUP
 *
 * For blocking we (obviously) need to provide the same guarantee as for
 * migration. However the means are completely different as there is no lock
 * chain to provide order. Instead we do:
 *
 *   1) smp_store_release(X->on_cpu, 0)
 *   2) smp_cond_load_acquire(!X->on_cpu)
 *
 * Example:
 *
 *   CPU0 (schedule)  CPU1 (try_to_wake_up) CPU2 (schedule)
 *
 *   LOCK rq(0)->lock LOCK X->pi_lock
 *   dequeue X
 *   sched-out X
 *   smp_store_release(X->on_cpu, 0);
 *
 *                    smp_cond_load_acquire(&X->on_cpu, !VAL);
 *                    X->state = WAKING
 *                    set_task_cpu(X,2)
 *
 *                    LOCK rq(2)->lock
 *                    enqueue X
 *                    X->state = RUNNING
 *                    UNLOCK rq(2)->lock
 *
 *                                          LOCK rq(2)->lock // orders against CPU1
 *                                          sched-out Z
 *                                          sched-in X
 *                                          UNLOCK rq(2)->lock
 *
 *                    UNLOCK X->pi_lock
 *   UNLOCK rq(0)->lock
 *
 *
 * However; for wakeups there is a second guarantee we must provide, namely we
 * must observe the state that lead to our wakeup. That is, not only must our
 * task observe its own prior state, it must also observe the stores prior to
 * its wakeup.
 *
 * This means that any means of doing remote wakeups must order the CPU doing
 * the wakeup against the CPU the task is going to end up running on. This,
 * however, is already required for the regular Program-Order guarantee above,
 * since the waking CPU is the one issueing the ACQUIRE (smp_cond_load_acquire).
 *
 */

/***
 * try_to_wake_up - wake up a thread
 * @p: the thread to be awakened
 * @state: the mask of task states that can be woken
 * @wake_flags: wake modifier flags (WF_*)
 *
 * Put it on the run-queue if it's not already there. The "current"
 * thread is always on the run-queue (except when the actual
 * re-schedule is in progress), and as such you're allowed to do
 * the simpler "current->state = TASK_RUNNING" to mark yourself
 * runnable without the overhead of this.
 *
 * Return: %true if @p was woken up, %false if it was already running.
 * or @state didn't match @p's state.
 */
static int try_to_wake_up(struct task_struct *p, unsigned int state,
			  int wake_flags)
{
	unsigned long flags;
	struct rq *rq;
	int cpu, success = 0;

	/*
	 * If we are going to wake up a thread waiting for CONDITION we
	 * need to ensure that CONDITION=1 done by the caller can not be
	 * reordered with p->state check below. This pairs with mb() in
	 * set_current_state() the waiting thread does.
	 */
	raw_spin_lock_irqsave(&p->pi_lock, flags);
	smp_mb__after_spinlock();
	if (!(p->state & state))
		goto out;

	trace_sched_waking(p);

	/* We're going to change ->state: */
	success = 1;
	cpu = task_cpu(p);

	/*
	 * Ensure we load p->on_rq _after_ p->state, otherwise it would
	 * be possible to, falsely, observe p->on_rq == 0 and get stuck
	 * in smp_cond_load_acquire() below.
	 *
	 * sched_ttwu_pending()                 try_to_wake_up()
	 *   [S] p->on_rq = 1;                  [L] P->state
	 *       UNLOCK rq->lock  -----.
	 *                              \
	 *				 +---   RMB
	 * schedule()                   /
	 *       LOCK rq->lock    -----'
	 *       UNLOCK rq->lock
	 *
	 * [task p]
	 *   [S] p->state = UNINTERRUPTIBLE     [L] p->on_rq
	 *
	 * Pairs with the UNLOCK+LOCK on rq->lock from the
	 * last wakeup of our task and the schedule that got our task
	 * current.
	 */
	smp_rmb();
	if (p->on_rq && ttwu_remote(p, wake_flags))
		goto stat;

#ifdef CONFIG_SMP
	/*
	 * Ensure we load p->on_cpu _after_ p->on_rq, otherwise it would be
	 * possible to, falsely, observe p->on_cpu == 0.
	 *
	 * One must be running (->on_cpu == 1) in order to remove oneself
	 * from the runqueue.
	 *
	 *  [S] ->on_cpu = 1;	[L] ->on_rq
	 *      UNLOCK rq->lock
	 *			RMB
	 *      LOCK   rq->lock
	 *  [S] ->on_rq = 0;    [L] ->on_cpu
	 *
	 * Pairs with the full barrier implied in the UNLOCK+LOCK on rq->lock
	 * from the consecutive calls to schedule(); the first switching to our
	 * task, the second putting it to sleep.
	 */
	smp_rmb();

	/*
	 * If the owning (remote) CPU is still in the middle of schedule() with
	 * this task as prev, wait until its done referencing the task.
	 *
	 * Pairs with the smp_store_release() in finish_task().
	 *
	 * This ensures that tasks getting woken will be fully ordered against
	 * their previous state and preserve Program Order.
	 */
	smp_cond_load_acquire(&p->on_cpu, !VAL);

	p->sched_contributes_to_load = !!task_contributes_to_load(p);
	p->state = TASK_WAKING;

	if (p->in_iowait) {
		delayacct_blkio_end(p);
		atomic_dec(&task_rq(p)->nr_iowait);
	}

	/* Check IDLE tasks suitable to run normal priority */
	if (idleprio_task(p)) {
		p->prio = idleprio_suitable(p)? p->normal_prio:NORMAL_PRIO;
		update_task_priodl(p);
	}

	cpu = select_task_rq(p, wake_flags);

	if (cpu != task_cpu(p)) {
		wake_flags |= WF_MIGRATED;
		set_task_cpu(p, cpu);
	}
#else /* CONFIG_SMP */
	if (p->in_iowait) {
		delayacct_blkio_end(p);
		atomic_dec(&task_rq(p)->nr_iowait);
	}
#endif

	rq = cpu_rq(cpu);
	raw_spin_lock(&rq->lock);

	update_rq_clock(rq);
	ttwu_do_activate(rq, p, wake_flags);
	check_preempt_curr(rq, p);

	raw_spin_unlock(&rq->lock);

stat:
	ttwu_stat(p, cpu, wake_flags);
out:
	raw_spin_unlock_irqrestore(&p->pi_lock, flags);

	return success;
}

/**
 * try_to_wake_up_local - try to wake up a local task with rq lock held
 * @p: the thread to be awakened
 *
 * Put @p on the run-queue if it's not already there. The caller must
 * ensure that local rq is locked and, @p is not the current task.
 */
static void try_to_wake_up_local(struct task_struct *p)
{
	struct rq *rq = task_rq(p);

	if (WARN_ON_ONCE(rq != this_rq()) ||
	    WARN_ON_ONCE(p == current))
		return;

	lockdep_assert_held(&rq->lock);

	if (!raw_spin_trylock(&p->pi_lock)) {
		/*
		 * This is OK, because current is on_cpu, which avoids it being
		 * picked for load-balance and preemption/IRQs are still
		 * disabled avoiding further scheduler activity on it and we've
		 * not yet picked a replacement task.
		 */
		raw_spin_unlock(&rq->lock);
		raw_spin_lock(&p->pi_lock);
		raw_spin_lock(&rq->lock);
	}

	if (!(p->state & TASK_NORMAL))
		goto out;

	trace_sched_waking(p);

	if (!task_queued(p)) {
		if (p->in_iowait) {
			delayacct_blkio_end(p);
			atomic_dec(&task_rq(p)->nr_iowait);
		}

		ttwu_activate(p, rq);
	}

	ttwu_do_wakeup(rq, p, 0);
	ttwu_stat(p, smp_processor_id(), 0);

out:
	raw_spin_unlock(&p->pi_lock);
}

/**
 * wake_up_process - Wake up a specific process
 * @p: The process to be woken up.
 *
 * Attempt to wake up the nominated process and move it to the set of runnable
 * processes.
 *
 * Return: 1 if the process was woken up, 0 if it was already running.
 *
 * It may be assumed that this function implies a write memory barrier before
 * changing the task state if and only if any tasks are woken up.
 */
int wake_up_process(struct task_struct *p)
{
	return try_to_wake_up(p, TASK_NORMAL, 0);
}
EXPORT_SYMBOL(wake_up_process);

int wake_up_state(struct task_struct *p, unsigned int state)
{
	return try_to_wake_up(p, state, 0);
}

static void time_slice_expired(struct task_struct *p, struct rq *rq);

/*
 * Perform scheduler related setup for a newly forked process p.
 * p is forked by current.
 */
int sched_fork(unsigned long __maybe_unused clone_flags, struct task_struct *p)
{
	unsigned long flags;
	int cpu = get_cpu();
	struct rq *rq = this_rq();

#ifdef CONFIG_PREEMPT_NOTIFIERS
	INIT_HLIST_HEAD(&p->preempt_notifiers);
#endif
	/* Should be reset in fork.c but done here for ease of PDS patching */
	p->on_cpu =
	p->on_rq =
	p->utime =
	p->stime =
	p->sched_time = 0;

	p->sl_level = pds_skiplist_random_level(p);
	INIT_SKIPLIST_NODE(&p->sl_node);

	/*
	 * We mark the process as NEW here. This guarantees that
	 * nobody will actually run it, and a signal or other external
	 * event cannot wake it up and insert it on the runqueue either.
	 */
	p->state = TASK_NEW;

	/*
	 * Make sure we do not leak PI boosting priority to the child.
	 */
	p->prio = current->normal_prio;

	/*
	 * Revert to default priority/policy on fork if requested.
	 */
	if (unlikely(p->sched_reset_on_fork)) {
		if (p->policy == SCHED_FIFO || p->policy == SCHED_RR) {
			p->policy = SCHED_NORMAL;
			p->normal_prio = normal_prio(p);
		}

		if (PRIO_TO_NICE(p->static_prio) < 0) {
			p->static_prio = NICE_TO_PRIO(0);
			p->normal_prio = p->static_prio;
		}

		p->prio = p->normal_prio;

		/*
		 * We don't need the reset flag anymore after the fork. It has
		 * fulfilled its duty:
		 */
		p->sched_reset_on_fork = 0;
	}

	/*
	 * Share the timeslice between parent and child, thus the
	 * total amount of pending timeslices in the system doesn't change,
	 * resulting in more scheduling fairness. But this limited the fork
	 * boost in one time slice. So punishment for run queue time slice only
	 * apply to IDLE and BATCH policy tasks.
	 * If it's negative, it won't matter since that's the same as being 0.
	 * as is its last_ran value.
	 */
	if (likely(p->policy != SCHED_FIFO)) {
		raw_spin_lock_irqsave(&rq->lock, flags);
		if (idleprio_task(p) || batch_task(p)) {
			rq->curr->time_slice /= 2;
			p->time_slice = rq->curr->time_slice;
#ifdef CONFIG_SCHED_HRTICK
			hrtick_start(rq, rq->curr->time_slice);
#endif
		} else
			p->time_slice = rq->curr->time_slice / 2;

		if (p->time_slice < RESCHED_US) {
			update_rq_clock(rq);
			time_slice_expired(p, rq);
		} else {
			/*
			 * child should has earlier deadline than parent,
			 * which will do child-runs-first in anticipation
			 * of an exec. usually avoids a lot of COW overhead.
			 */
			p->deadline -= MIN_VISIBLE_DEADLINE;
			update_task_priodl(p);
		}
		raw_spin_unlock_irqrestore(&rq->lock, flags);
	} else
		update_task_priodl(p);

	/*
	 * The child is not yet in the pid-hash so no cgroup attach races,
	 * and the cgroup is pinned to this child due to cgroup_fork()
	 * is ran before sched_fork().
	 *
	 * Silence PROVE_RCU.
	 */
	raw_spin_lock_irqsave(&p->pi_lock, flags);
	/*
	 * We're setting the CPU for the first time, we don't migrate,
	 * so use __set_task_cpu().
	 */
	__set_task_cpu(p, cpu);
	raw_spin_unlock_irqrestore(&p->pi_lock, flags);

#ifdef CONFIG_SCHED_INFO
	if (unlikely(sched_info_on()))
		memset(&p->sched_info, 0, sizeof(p->sched_info));
#endif
	init_task_preempt_count(p);

	put_cpu();
	return 0;
}

#ifdef CONFIG_SCHEDSTATS

DEFINE_STATIC_KEY_FALSE(sched_schedstats);
static bool __initdata __sched_schedstats = false;

static void set_schedstats(bool enabled)
{
	if (enabled)
		static_branch_enable(&sched_schedstats);
	else
		static_branch_disable(&sched_schedstats);
}

void force_schedstat_enabled(void)
{
	if (!schedstat_enabled()) {
		pr_info("kernel profiling enabled schedstats, disable via kernel.sched_schedstats.\n");
		static_branch_enable(&sched_schedstats);
	}
}

static int __init setup_schedstats(char *str)
{
	int ret = 0;
	if (!str)
		goto out;

	/*
	 * This code is called before jump labels have been set up, so we can't
	 * change the static branch directly just yet.  Instead set a temporary
	 * variable so init_schedstats() can do it later.
	 */
	if (!strcmp(str, "enable")) {
		__sched_schedstats = true;
		ret = 1;
	} else if (!strcmp(str, "disable")) {
		__sched_schedstats = false;
		ret = 1;
	}
out:
	if (!ret)
		pr_warn("Unable to parse schedstats=\n");

	return ret;
}
__setup("schedstats=", setup_schedstats);

static void __init init_schedstats(void)
{
	set_schedstats(__sched_schedstats);
}

#ifdef CONFIG_PROC_SYSCTL
int sysctl_schedstats(struct ctl_table *table, int write,
			 void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	int err;
	int state = static_branch_likely(&sched_schedstats);

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	t = *table;
	t.data = &state;
	err = proc_dointvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;
	if (write)
		set_schedstats(state);
	return err;
}
#endif /* CONFIG_PROC_SYSCTL */
#else  /* !CONFIG_SCHEDSTATS */
static inline void init_schedstats(void) {}
#endif /* CONFIG_SCHEDSTATS */

/*
 * wake_up_new_task - wake up a newly created task for the first time.
 *
 * This function will do some initial scheduler statistics housekeeping
 * that must be done for every newly created context, then puts the task
 * on the runqueue and wakes it.
 */
void wake_up_new_task(struct task_struct *p)
{
	unsigned long flags;
	struct rq *rq;

	raw_spin_lock_irqsave(&p->pi_lock, flags);

	p->state = TASK_RUNNING;

	rq = cpu_rq(select_task_rq(p, 0));
#ifdef CONFIG_SMP
	/*
	 * Fork balancing, do it here and not earlier because:
	 * - cpus_allowed can change in the fork path
	 * - any previously selected CPU might disappear through hotplug
	 * Use __set_task_cpu() to avoid calling sched_class::migrate_task_rq,
	 * as we're not fully set-up yet.
	 */
	__set_task_cpu(p, cpu_of(rq));
#endif

	raw_spin_lock(&rq->lock);

	update_rq_clock(rq);
	activate_task(p, rq);
	trace_sched_wakeup_new(p);
	check_preempt_curr(rq, p);

	raw_spin_unlock(&rq->lock);
	raw_spin_unlock_irqrestore(&p->pi_lock, flags);
}

#ifdef CONFIG_PREEMPT_NOTIFIERS

static DEFINE_STATIC_KEY_FALSE(preempt_notifier_key);

void preempt_notifier_inc(void)
{
	static_branch_inc(&preempt_notifier_key);
}
EXPORT_SYMBOL_GPL(preempt_notifier_inc);

void preempt_notifier_dec(void)
{
	static_branch_dec(&preempt_notifier_key);
}
EXPORT_SYMBOL_GPL(preempt_notifier_dec);

/**
 * preempt_notifier_register - tell me when current is being preempted & rescheduled
 * @notifier: notifier struct to register
 */
void preempt_notifier_register(struct preempt_notifier *notifier)
{
	if (!static_branch_unlikely(&preempt_notifier_key))
		WARN(1, "registering preempt_notifier while notifiers disabled\n");

	hlist_add_head(&notifier->link, &current->preempt_notifiers);
}
EXPORT_SYMBOL_GPL(preempt_notifier_register);

/**
 * preempt_notifier_unregister - no longer interested in preemption notifications
 * @notifier: notifier struct to unregister
 *
 * This is *not* safe to call from within a preemption notifier.
 */
void preempt_notifier_unregister(struct preempt_notifier *notifier)
{
	hlist_del(&notifier->link);
}
EXPORT_SYMBOL_GPL(preempt_notifier_unregister);

static void __fire_sched_in_preempt_notifiers(struct task_struct *curr)
{
	struct preempt_notifier *notifier;

	hlist_for_each_entry(notifier, &curr->preempt_notifiers, link)
		notifier->ops->sched_in(notifier, raw_smp_processor_id());
}

static __always_inline void fire_sched_in_preempt_notifiers(struct task_struct *curr)
{
	if (static_branch_unlikely(&preempt_notifier_key))
		__fire_sched_in_preempt_notifiers(curr);
}

static void
__fire_sched_out_preempt_notifiers(struct task_struct *curr,
				   struct task_struct *next)
{
	struct preempt_notifier *notifier;

	hlist_for_each_entry(notifier, &curr->preempt_notifiers, link)
		notifier->ops->sched_out(notifier, next);
}

static __always_inline void
fire_sched_out_preempt_notifiers(struct task_struct *curr,
				 struct task_struct *next)
{
	if (static_branch_unlikely(&preempt_notifier_key))
		__fire_sched_out_preempt_notifiers(curr, next);
}

#else /* !CONFIG_PREEMPT_NOTIFIERS */

static inline void fire_sched_in_preempt_notifiers(struct task_struct *curr)
{
}

static inline void
fire_sched_out_preempt_notifiers(struct task_struct *curr,
				 struct task_struct *next)
{
}

#endif /* CONFIG_PREEMPT_NOTIFIERS */

static inline void prepare_task(struct task_struct *next)
{
	/*
	 * Claim the task as running, we do this before switching to it
	 * such that any running task will have this set.
	 */
	next->on_cpu = 1;
}

static inline void finish_task(struct task_struct *prev)
{
#ifdef CONFIG_SMP
	/*
	 * After ->on_cpu is cleared, the task can be moved to a different CPU.
	 * We must ensure this doesn't happen until the switch is completely
	 * finished.
	 *
	 * In particular, the load of prev->state in finish_task_switch() must
	 * happen before this.
	 *
	 * Pairs with the smp_cond_load_acquire() in try_to_wake_up().
	 */
	smp_store_release(&prev->on_cpu, 0);
#else
	prev->on_cpu = 0;
#endif
}

static inline void
prepare_lock_switch(struct rq *rq, struct task_struct *next)
{
	/*
	 * Since the runqueue lock will be released by the next
	 * task (which is an invalid locking op but in the case
	 * of the scheduler it's an obvious special-case), so we
	 * do an early lockdep release here:
	 */
	spin_release(&rq->lock.dep_map, 1, _THIS_IP_);
#ifdef CONFIG_DEBUG_SPINLOCK
	/* this is a valid case when another task releases the spinlock */
	rq->lock.owner = next;
#endif
}

static inline void finish_lock_switch(struct rq *rq)
{
	/*
	 * If we are tracking spinlock dependencies then we have to
	 * fix up the runqueue lock - which gets 'carried over' from
	 * prev into current:
	 */
	spin_acquire(&rq->lock.dep_map, 0, 0, _THIS_IP_);
	raw_spin_unlock_irq(&rq->lock);
}

/**
 * prepare_task_switch - prepare to switch tasks
 * @rq: the runqueue preparing to switch
 * @next: the task we are going to switch to.
 *
 * This is called with the rq lock held and interrupts off. It must
 * be paired with a subsequent finish_task_switch after the context
 * switch.
 *
 * prepare_task_switch sets up locking and calls architecture specific
 * hooks.
 */
static inline void
prepare_task_switch(struct rq *rq, struct task_struct *prev,
		    struct task_struct *next)
{
	sched_info_switch(rq, prev, next);
	perf_event_task_sched_out(prev, next);
	fire_sched_out_preempt_notifiers(prev, next);
	prepare_task(next);
	prepare_arch_switch(next);
}

/**
 * finish_task_switch - clean up after a task-switch
 * @rq: runqueue associated with task-switch
 * @prev: the thread we just switched away from.
 *
 * finish_task_switch must be called after the context switch, paired
 * with a prepare_task_switch call before the context switch.
 * finish_task_switch will reconcile locking set up by prepare_task_switch,
 * and do any other architecture-specific cleanup actions.
 *
 * Note that we may have delayed dropping an mm in context_switch(). If
 * so, we finish that here outside of the runqueue lock.  (Doing it
 * with the lock held can cause deadlocks; see schedule() for
 * details.)
 *
 * The context switch have flipped the stack from under us and restored the
 * local variables which were saved when this task called schedule() in the
 * past. prev == current is still correct but we need to recalculate this_rq
 * because prev may have moved to another CPU.
 */
static struct rq *finish_task_switch(struct task_struct *prev)
	__releases(rq->lock)
{
	struct rq *rq = this_rq();
	struct mm_struct *mm = rq->prev_mm;
	long prev_state;

	/*
	 * The previous task will have left us with a preempt_count of 2
	 * because it left us after:
	 *
	 *	schedule()
	 *	  preempt_disable();			// 1
	 *	  __schedule()
	 *	    raw_spin_lock_irq(&rq->lock)	// 2
	 *
	 * Also, see FORK_PREEMPT_COUNT.
	 */
	if (WARN_ONCE(preempt_count() != 2*PREEMPT_DISABLE_OFFSET,
		      "corrupted preempt_count: %s/%d/0x%x\n",
		      current->comm, current->pid, preempt_count()))
		preempt_count_set(FORK_PREEMPT_COUNT);

	rq->prev_mm = NULL;

	/*
	 * A task struct has one reference for the use as "current".
	 * If a task dies, then it sets TASK_DEAD in tsk->state and calls
	 * schedule one last time. The schedule call will never return, and
	 * the scheduled task must drop that reference.
	 *
	 * We must observe prev->state before clearing prev->on_cpu (in
	 * finish_task), otherwise a concurrent wakeup can get prev
	 * running on another CPU and we could rave with its RUNNING -> DEAD
	 * transition, resulting in a double drop.
	 */
	prev_state = prev->state;
	vtime_task_switch(prev);
	perf_event_task_sched_in(prev, current);
	finish_task(prev);
	finish_lock_switch(rq);
	finish_arch_post_lock_switch();

	fire_sched_in_preempt_notifiers(current);
	/*
	 * When switching through a kernel thread, the loop in
	 * membarrier_{private,global}_expedited() may have observed that
	 * kernel thread and not issued an IPI. It is therefore possible to
	 * schedule between user->kernel->user threads without passing though
	 * switch_mm(). Membarrier requires a barrier after storing to
	 * rq->curr, before returning to userspace, so provide them here:
	 *
	 * - a full memory barrier for {PRIVATE,GLOBAL}_EXPEDITED, implicitly
	 *   provided by mmdrop(),
	 * - a sync_core for SYNC_CORE.
	 */
	if (mm) {
		membarrier_mm_sync_core_before_usermode(mm);
		mmdrop(mm);
	}
	if (unlikely(prev_state & (TASK_DEAD|TASK_PARKED))) {
		switch (prev_state) {
		case TASK_DEAD:
			/*
			 * Remove function-return probe instances associated with this
			 * task and put them back on the free list.
			 */
			kprobe_flush_task(prev);

			/* Task is done with its stack. */
			put_task_stack(prev);

			put_task_struct(prev);
			break;

		case TASK_PARKED:
			kthread_park_complete(prev);
			break;
		}
	}

	return rq;
}

/**
 * schedule_tail - first thing a freshly forked thread must call.
 * @prev: the thread we just switched away from.
 */
asmlinkage __visible void schedule_tail(struct task_struct *prev)
	__releases(rq->lock)
{
	struct rq *rq;

	/*
	 * New tasks start with FORK_PREEMPT_COUNT, see there and
	 * finish_task_switch() for details.
	 *
	 * finish_task_switch() will drop rq->lock() and lower preempt_count
	 * and the preempt_enable() will end up enabling preemption (on
	 * PREEMPT_COUNT kernels).
	 */

	rq = finish_task_switch(prev);
	preempt_enable();

	if (current->set_child_tid)
		put_user(task_pid_vnr(current), current->set_child_tid);
}

/*
 * context_switch - switch to the new MM and the new thread's register state.
 */
static __always_inline struct rq *
context_switch(struct rq *rq, struct task_struct *prev,
	       struct task_struct *next)
{
	struct mm_struct *mm, *oldmm;

	prepare_task_switch(rq, prev, next);

	mm = next->mm;
	oldmm = prev->active_mm;
	/*
	 * For paravirt, this is coupled with an exit in switch_to to
	 * combine the page table reload and the switch backend into
	 * one hypercall.
	 */
	arch_start_context_switch(prev);

	/*
	 * If mm is non-NULL, we pass through switch_mm(). If mm is
	 * NULL, we will pass through mmdrop() in finish_task_switch().
	 * Both of these contain the full memory barrier required by
	 * membarrier after storing to rq->curr, before returning to
	 * user-space.
	 */
	if (!mm) {
		next->active_mm = oldmm;
		mmgrab(oldmm);
		enter_lazy_tlb(oldmm, next);
	} else
		switch_mm_irqs_off(oldmm, mm, next);

	if (!prev->mm) {
		prev->active_mm = NULL;
		rq->prev_mm = oldmm;
	}

	prepare_lock_switch(rq, next);

	/* Here we just switch the register state and the stack. */
	switch_to(prev, next, prev);
	barrier();

	return finish_task_switch(prev);
}

/*
 * nr_running, nr_uninterruptible and nr_context_switches:
 *
 * externally visible scheduler statistics: current number of runnable
 * threads, total number of context switches performed since bootup.
 */
unsigned long nr_running(void)
{
	unsigned long i, sum = 0;

	for_each_online_cpu(i)
		sum += cpu_rq(i)->nr_running;

	return sum;
}

/*
 * Check if only the current task is running on the CPU.
 *
 * Caution: this function does not check that the caller has disabled
 * preemption, thus the result might have a time-of-check-to-time-of-use
 * race.  The caller is responsible to use it correctly, for example:
 *
 * - from a non-preemptable section (of course)
 *
 * - from a thread that is bound to a single CPU
 *
 * - in a loop with very short iterations (e.g. a polling loop)
 */
bool single_task_running(void)
{
	return raw_rq()->nr_running == 1;
}
EXPORT_SYMBOL(single_task_running);

unsigned long long nr_context_switches(void)
{
	int i;
	unsigned long long sum = 0;

	for_each_possible_cpu(i)
		sum += cpu_rq(i)->nr_switches;

	return sum;
}

/*
 * IO-wait accounting, and how its mostly bollocks (on SMP).
 *
 * The idea behind IO-wait account is to account the idle time that we could
 * have spend running if it were not for IO. That is, if we were to improve the
 * storage performance, we'd have a proportional reduction in IO-wait time.
 *
 * This all works nicely on UP, where, when a task blocks on IO, we account
 * idle time as IO-wait, because if the storage were faster, it could've been
 * running and we'd not be idle.
 *
 * This has been extended to SMP, by doing the same for each CPU. This however
 * is broken.
 *
 * Imagine for instance the case where two tasks block on one CPU, only the one
 * CPU will have IO-wait accounted, while the other has regular idle. Even
 * though, if the storage were faster, both could've ran at the same time,
 * utilising both CPUs.
 *
 * This means, that when looking globally, the current IO-wait accounting on
 * SMP is a lower bound, by reason of under accounting.
 *
 * Worse, since the numbers are provided per CPU, they are sometimes
 * interpreted per CPU, and that is nonsensical. A blocked task isn't strictly
 * associated with any one particular CPU, it can wake to another CPU than it
 * blocked on. This means the per CPU IO-wait number is meaningless.
 *
 * Task CPU affinities can make all that even more 'interesting'.
 */

unsigned long nr_iowait(void)
{
	unsigned long i, sum = 0;

	for_each_possible_cpu(i)
		sum += atomic_read(&cpu_rq(i)->nr_iowait);

	return sum;
}

/*
 * Consumers of these two interfaces, like for example the cpufreq menu
 * governor are using nonsensical data. Boosting frequency for a CPU that has
 * IO-wait which might not even end up running the task when it does become
 * runnable.
 */

unsigned long nr_iowait_cpu(int cpu)
{
	struct rq *this = cpu_rq(cpu);
	return atomic_read(&this->nr_iowait);
}

/* Beyond a task running on this CPU, load is equal everywhere on PDS, so we
 * base it on the number of running or queued tasks with their ->rq pointer
 * set to this CPU as being the CPU they're more likely to run on. */
void get_iowait_load(unsigned long *nr_waiters, unsigned long *load)
{
	struct rq *rq = this_rq();

	*nr_waiters = atomic_read(&rq->nr_iowait);
	*load = rq->nr_running;
}

DEFINE_PER_CPU(struct kernel_stat, kstat);
DEFINE_PER_CPU(struct kernel_cpustat, kernel_cpustat);

EXPORT_PER_CPU_SYMBOL(kstat);
EXPORT_PER_CPU_SYMBOL(kernel_cpustat);

static inline void pds_update_curr(struct rq *rq, struct task_struct *p)
{
	s64 ns = rq->clock_task - p->last_ran;

	p->sched_time += ns;
	account_group_exec_runtime(p, ns);

	/* time_slice accounting is done in usecs to avoid overflow on 32bit */
	if (likely(p->policy != SCHED_FIFO))
		p->time_slice -= NS_TO_US(ns);
	p->last_ran = rq->clock_task;
}

/*
 * Return accounted runtime for the task.
 * Return separately the current's pending runtime that have not been
 * accounted yet.
 */
unsigned long long task_sched_runtime(struct task_struct *p)
{
	unsigned long flags;
	struct rq *rq;
	raw_spinlock_t *lock;
	u64 ns;

#if defined(CONFIG_64BIT) && defined(CONFIG_SMP)
	/*
	 * 64-bit doesn't need locks to atomically read a 64-bit value.
	 * So we have a optimization chance when the task's delta_exec is 0.
	 * Reading ->on_cpu is racy, but this is ok.
	 *
	 * If we race with it leaving CPU, we'll take a lock. So we're correct.
	 * If we race with it entering CPU, unaccounted time is 0. This is
	 * indistinguishable from the read occurring a few cycles earlier.
	 * If we see ->on_cpu without ->on_rq, the task is leaving, and has
	 * been accounted, so we're correct here as well.
	 */
	if (!p->on_cpu || !task_on_rq_queued(p))
		return tsk_seruntime(p);
#endif

	rq = task_access_lock_irqsave(p, &lock, &flags);
	/*
	 * Must be ->curr _and_ ->on_rq.  If dequeued, we would
	 * project cycles that may never be accounted to this
	 * thread, breaking clock_gettime().
	 */
	if (p == rq->curr && task_on_rq_queued(p)) {
		update_rq_clock(rq);
		pds_update_curr(rq, p);
	}
	ns = tsk_seruntime(p);
	task_access_unlock_irqrestore(p, lock, &flags);

	return ns;
}

/*
 * Functions to test for when SCHED_ISO tasks have used their allocated
 * quota as real time scheduling and convert them back to SCHED_NORMAL.
 * Where possible, the data is tested lockless, to avoid grabbing iso_lock
 * because the occasional inaccurate result won't matter. However the
 * tick data is only ever modified under lock. iso_refractory is only simply
 * set to 0 or 1 so it's not worth grabbing the lock yet again for that.
 */

/*
 * Test if SCHED_ISO tasks have run longer than their alloted period as RT
 * tasks and set the refractory flag if necessary. There is 10% hysteresis
 * for unsetting the flag. 115/128 is ~90/100 as a fast shift instead of a
 * slow division.
 */
static inline bool test_ret_isorefractory(struct rq *rq)
{
	if (likely(!rq->iso_refractory)) {
		if (rq->iso_ticks > ISO_PERIOD * sched_iso_cpu)
			return (rq->iso_refractory = true);
	} else {
		if (rq->iso_ticks < ISO_PERIOD * (sched_iso_cpu * 115 / 128))
			return (rq->iso_refractory = false);
	}
	return rq->iso_refractory;
}

static inline void iso_tick(struct rq *rq)
{
	rq->iso_ticks += 100;
}

/* No SCHED_ISO task was running so decrease rq->iso_ticks */
static inline void no_iso_tick(struct rq *rq)
{
	if (rq->iso_ticks) {
		rq->iso_ticks -= rq->iso_ticks / ISO_PERIOD + 1;
		if (unlikely(rq->iso_refractory && rq->iso_ticks <
		    ISO_PERIOD * (sched_iso_cpu * 115 / 128)))
			rq->iso_refractory = false;
	}
}

/* This manages tasks that have run out of timeslice during a scheduler_tick */
static inline void pds_scheduler_task_tick(struct rq *rq)
{
	struct task_struct *p = rq->curr;

	if (is_idle_task(p))
		return;

	pds_update_curr(rq, p);

	cpufreq_update_util(rq, 0);
	/*
	 * If a SCHED_ISO task is running we increment the iso_ticks. In
	 * order to prevent SCHED_ISO tasks from causing starvation in the
	 * presence of true RT tasks we account those as iso_ticks as well.
	 */
	if (unlikely(rt_task(p) || task_running_iso(p))) {
		if (rq->iso_ticks <= (ISO_PERIOD * 128) - 128)
			iso_tick(rq);
	} else
		no_iso_tick(rq);

	if (unlikely(iso_task(p))) {
		if (unlikely(test_ret_isorefractory(rq))) {
			if (task_running_iso(p)) {
				/*
				 * SCHED_ISO task is running as RT and limit
				 * has been hit. Force it to reschedule as
				 * SCHED_NORMAL by zeroing its time_slice
				 */
				p->time_slice = 0;
			}
		}
	}

	/* SCHED_FIFO tasks never run out of timeslice. */
	if (unlikely(p->policy == SCHED_FIFO))
		return;
	/*
	 * Tasks that were scheduled in the first half of a tick are not
	 * allowed to run into the 2nd half of the next tick if they will
	 * run out of time slice in the interim. Otherwise, if they have
	 * less than RESCHED_US μs of time slice left they will be rescheduled.
	 */
	if (p->time_slice - rq->dither >= RESCHED_US)
		return;

	/**
	 * p->time_slice < RESCHED_US. We will modify task_struct under
	 * rq lock as p is rq->curr
	 */
	__set_tsk_resched(p);
}

#ifdef CONFIG_SMP

#ifdef CONFIG_SCHED_SMT
static int active_load_balance_cpu_stop(void *data)
{
	struct rq *origin_rq, *rq = this_rq();
	struct task_struct *p = data;
	cpumask_t tmp;
	unsigned long flags;

	origin_rq = rq;
	local_irq_save(flags);

	raw_spin_lock(&p->pi_lock);
	raw_spin_lock(&rq->lock);

	/*
	 * _something_ may have changed the task, double check again
	 */
	if (task_queued(p) && task_rq(p) == rq &&
	    cpumask_and(&tmp, &p->cpus_allowed, &sched_cpu_sg_idle_mask))
		rq = __migrate_task(rq, p, cpumask_any(&tmp));

	origin_rq->active_balance = 0;

	raw_spin_unlock(&rq->lock);
	raw_spin_unlock(&p->pi_lock);

	local_irq_restore(flags);

	return 0;
}

static __latent_entropy void pds_run_rebalance(struct softirq_action *h)
{
	struct rq *this_rq = this_rq();
	unsigned long flags;
	struct task_struct *curr;
	cpumask_t tmp;

	raw_spin_lock_irqsave(&this_rq->lock, flags);
	curr = this_rq->curr;
	if (cpumask_and(&tmp, &curr->cpus_allowed, &sched_cpu_sg_idle_mask)) {
		int active_balance = 0;

		if (likely(!this_rq->active_balance)) {
			this_rq->active_balance = 1;
			active_balance = 1;
		}

		raw_spin_unlock_irqrestore(&this_rq->lock, flags);

		if (likely(active_balance))
			stop_one_cpu_nowait(cpu_of(this_rq),
					    active_load_balance_cpu_stop, curr,
					    &this_rq->active_balance_work);
	} else
		raw_spin_unlock_irqrestore(&this_rq->lock, flags);
}

static inline bool pds_sg_balance(struct rq *rq)
{
	int cpu;
	struct task_struct *p;

	/*
	 * Quick exit if no idle sibling group to be balanced to, or
	 * in case cpu has no smt capability, which sched_cpu_sg_idle_mask will
	 * not be changed.
	 */
	if (cpumask_empty(&sched_cpu_sg_idle_mask))
		return false;

	/*
	 * Exit if any idle cpu in this smt group
	 */
	cpu = cpu_of(rq);
	if (cpumask_intersects(cpu_smt_mask(cpu),
			       &sched_rq_queued_masks[SCHED_RQ_EMPTY]))
		return false;

	/*
	 * First cpu in smt group does not do smt balance, unless
	 * other cpu is smt balance suppressed.
	 */
	if (cpu == cpumask_first(cpu_smt_mask(cpu)) &&
	    !cpumask_intersects(cpu_smt_mask(cpu), &sched_cpu_sb_suppress_mask))
		return false;

	p = rq->curr;
	if (cpumask_intersects(&p->cpus_allowed, &sched_cpu_sg_idle_mask)) {
		cpumask_andnot(&sched_cpu_sb_suppress_mask,
			       &sched_cpu_sb_suppress_mask,
			       cpu_smt_mask(cpu));
		raise_softirq(SCHED_SOFTIRQ);

		return true;
	}

	cpumask_set_cpu(cpu, &sched_cpu_sb_suppress_mask);
	return false;
}
#endif /* CONFIG_SCHED_SMT */

/**
 * PDS load balance function, be called in scheduler_tick()
 *
 * return: true if balance happened and rq->lock released, otherwise false.
 * context: interrupt disabled, rq->lock
 */
static inline bool pds_load_balance(struct rq *rq)
{
	int level, preempt_level;
	struct skiplist_node *node;
	struct task_struct *p;

	if (rq->clock < rq->next_balance)
		return false;

	rq->next_balance = (rq->clock & BALANCE_INTERVAL_MASK) + rq->balance_inc;

	/*
	 * this function is called when rq is locked and nr_running >= 2
	 */
	if (unlikely((node = rq->sl_header.next[0]->next[0]) == &rq->sl_header))
		return false;

	p = skiplist_entry(node, struct task_struct, sl_node);

	/*
	 * balance preempt start from SCHED_RQ_IDLE mask,
	 * SCHED_RQ_EMPTY mask should be handled in ttwu
	 */
	level = find_next_bit(sched_rq_queued_masks_bitmap,
			      NR_SCHED_RQ_QUEUED_LEVEL, SCHED_RQ_IDLE);
	preempt_level = task_running_policy_level(p, rq);

	while (level < preempt_level) {
		cpumask_t check;

		if (cpumask_and(&check, &sched_rq_queued_masks[level],
				&p->cpus_allowed)) {
			WARN_ONCE(cpumask_test_cpu(cpu_of(rq), &check),
				  "pds: %d - %d, %d, %llu %d, %d, %llu",
				  level,
				  preempt_level, p->prio, p->deadline,
				  task_running_policy_level(rq->curr, rq),
				  rq->curr->prio, rq->curr->deadline);

			raw_spin_unlock(&rq->lock);
			raw_spin_lock(&p->pi_lock);
			raw_spin_lock(&rq->lock);

			/*
			 * _something_ may have changed the task,
			 * double check again
			 */
			if (likely(!p->on_cpu && task_on_rq_queued(p) &&
				   rq == task_rq(p)))
				rq = __migrate_task(rq, p, cpumask_any(&check));

			raw_spin_unlock(&rq->lock);
			raw_spin_unlock(&p->pi_lock);

			return true;
		}

		level = find_next_bit(sched_rq_queued_masks_bitmap,
				      NR_SCHED_RQ_QUEUED_LEVEL, ++level);
	}

	return false;
}

static inline bool pds_trigger_balance(struct rq *rq)
{
	if (0 == rq->nr_running)
		return false;

	/*
	 * Sibling balance only happens when only one task is running
	 * When no task is running, there will be no need to balance
	 * When there are queued tasks in this rq, they will be handled
	 * in policy fair balance
	 */
	if (1 == rq->nr_running) {
#ifdef CONFIG_SCHED_SMT
		pds_sg_balance(rq);
#endif
		return false;
	} else {
		return pds_load_balance(rq);
	}
}
#endif /* CONFIG_SMP */

/*
 * This function gets called by the timer code, with HZ frequency.
 * We call it with interrupts disabled.
 */
void scheduler_tick(void)
{
	int cpu __maybe_unused = smp_processor_id();
	struct rq *rq = cpu_rq(cpu);

	sched_clock_tick();

	raw_spin_lock(&rq->lock);
	update_rq_clock(rq);

	pds_scheduler_task_tick(rq);
	update_sched_rq_queued_masks_normal(rq);
	calc_global_load_tick(rq);
	rq->last_tick = rq->clock;

#ifdef CONFIG_SMP
	if (!pds_trigger_balance(rq))
#endif
	raw_spin_unlock(&rq->lock);

	perf_event_task_tick();
}

#ifdef CONFIG_NO_HZ_FULL
struct tick_work {
	int			cpu;
	struct delayed_work	work;
};

static struct tick_work __percpu *tick_work_cpu;

static void sched_tick_remote(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct tick_work *twork = container_of(dwork, struct tick_work, work);
	int cpu = twork->cpu;
	struct rq *rq = cpu_rq(cpu);
	unsigned long flags;

	/*
	 * Handle the tick only if it appears the remote CPU is running in full
	 * dynticks mode. The check is racy by nature, but missing a tick or
	 * having one too much is no big deal because the scheduler tick updates
	 * statistics and checks timeslices in a time-independent way, regardless
	 * of when exactly it is running.
	 */
	if (!idle_cpu(cpu) && tick_nohz_tick_stopped_cpu(cpu)) {
		struct task_struct *curr;
		u64 delta;

		raw_spin_lock_irqsave(&rq->lock, flags);
		update_rq_clock(rq);
		curr = rq->curr;
		delta = rq_clock_task(rq) - curr->last_ran;

		/*
		 * Make sure the next tick runs within a reasonable
		 * amount of time.
		 */
		WARN_ON_ONCE(delta > (u64)NSEC_PER_SEC * 3);
		pds_scheduler_task_tick(rq);
		update_sched_rq_queued_masks_normal(rq);
		raw_spin_unlock_irqrestore(&rq->lock, flags);
	}

	/*
	 * Run the remote tick once per second (1Hz). This arbitrary
	 * frequency is large enough to avoid overload but short enough
	 * to keep scheduler internal stats reasonably up to date.
	 */
	queue_delayed_work(system_unbound_wq, dwork, HZ);
}

static void sched_tick_start(int cpu)
{
	struct tick_work *twork;

	if (housekeeping_cpu(cpu, HK_FLAG_TICK))
		return;

	WARN_ON_ONCE(!tick_work_cpu);

	twork = per_cpu_ptr(tick_work_cpu, cpu);
	twork->cpu = cpu;
	INIT_DELAYED_WORK(&twork->work, sched_tick_remote);
	queue_delayed_work(system_unbound_wq, &twork->work, HZ);
}

#ifdef CONFIG_HOTPLUG_CPU
static void sched_tick_stop(int cpu)
{
	struct tick_work *twork;

	if (housekeeping_cpu(cpu, HK_FLAG_TICK))
		return;

	WARN_ON_ONCE(!tick_work_cpu);

	twork = per_cpu_ptr(tick_work_cpu, cpu);
	cancel_delayed_work_sync(&twork->work);
}
#endif /* CONFIG_HOTPLUG_CPU */

int __init sched_tick_offload_init(void)
{
	tick_work_cpu = alloc_percpu(struct tick_work);
	BUG_ON(!tick_work_cpu);

	return 0;
}

#else /* !CONFIG_NO_HZ_FULL */
static inline void sched_tick_start(int cpu) { }
static inline void sched_tick_stop(int cpu) { }
#endif

#if defined(CONFIG_PREEMPT) && (defined(CONFIG_DEBUG_PREEMPT) || \
				defined(CONFIG_PREEMPT_TRACER))
/*
 * If the value passed in is equal to the current preempt count
 * then we just disabled preemption. Start timing the latency.
 */
static inline void preempt_latency_start(int val)
{
	if (preempt_count() == val) {
		unsigned long ip = get_lock_parent_ip();
#ifdef CONFIG_DEBUG_PREEMPT
		current->preempt_disable_ip = ip;
#endif
		trace_preempt_off(CALLER_ADDR0, ip);
	}
}

void preempt_count_add(int val)
{
#ifdef CONFIG_DEBUG_PREEMPT
	/*
	 * Underflow?
	 */
	if (DEBUG_LOCKS_WARN_ON((preempt_count() < 0)))
		return;
#endif
	__preempt_count_add(val);
#ifdef CONFIG_DEBUG_PREEMPT
	/*
	 * Spinlock count overflowing soon?
	 */
	DEBUG_LOCKS_WARN_ON((preempt_count() & PREEMPT_MASK) >=
				PREEMPT_MASK - 10);
#endif
	preempt_latency_start(val);
}
EXPORT_SYMBOL(preempt_count_add);
NOKPROBE_SYMBOL(preempt_count_add);

/*
 * If the value passed in equals to the current preempt count
 * then we just enabled preemption. Stop timing the latency.
 */
static inline void preempt_latency_stop(int val)
{
	if (preempt_count() == val)
		trace_preempt_on(CALLER_ADDR0, get_lock_parent_ip());
}

void preempt_count_sub(int val)
{
#ifdef CONFIG_DEBUG_PREEMPT
	/*
	 * Underflow?
	 */
	if (DEBUG_LOCKS_WARN_ON(val > preempt_count()))
		return;
	/*
	 * Is the spinlock portion underflowing?
	 */
	if (DEBUG_LOCKS_WARN_ON((val < PREEMPT_MASK) &&
			!(preempt_count() & PREEMPT_MASK)))
		return;
#endif

	preempt_latency_stop(val);
	__preempt_count_sub(val);
}
EXPORT_SYMBOL(preempt_count_sub);
NOKPROBE_SYMBOL(preempt_count_sub);

#else
static inline void preempt_latency_start(int val) { }
static inline void preempt_latency_stop(int val) { }
#endif

/*
 * The time_slice is only refilled when it is empty and that is when we set a
 * new deadline.
 */
static void time_slice_expired(struct task_struct *p, struct rq *rq)
{
	if (unlikely(p->policy == SCHED_FIFO))
		return;
	p->time_slice = timeslice();

	if (unlikely(p->policy == SCHED_RR))
		return;
	if (p->policy == SCHED_NORMAL) {
		p->deadline /= 2;
		p->deadline += (rq->clock + task_deadline_diff(p)) / 2;
	} else
		p->deadline = rq->clock + task_deadline_diff(p);

	update_task_priodl(p);
}

/*
 * Timeslices below RESCHED_US are considered as good as expired as there's no
 * point rescheduling when there's so little time left. SCHED_BATCH tasks
 * have been flagged be not latency sensitive and likely to be fully CPU
 * bound so every time they're rescheduled they have their time_slice
 * refilled, but get a new later deadline to have little effect on
 * SCHED_NORMAL tasks.

 */
static inline void check_deadline(struct task_struct *p, struct rq *rq)
{
	if (rq->idle == p)
		return;

	pds_update_curr(rq, p);

	if (p->time_slice < RESCHED_US || batch_task(p)) {
		time_slice_expired(p, rq);
		if (task_queued(p))
			requeue_task(p, rq);
	}
}

#ifdef	CONFIG_SMP

#define SCHED_RQ_NR_MIGRATION (32UL)
/*
 * Migrate pending tasks in @rq to @dest_cpu
 * Will try to migrate mininal of half of @rq nr_running tasks and
 * SCHED_RQ_NR_MIGRATION to @dest_cpu
 */
static inline int migrate_pending_tasks(struct rq *rq, int dest_cpu)
{
	int nr_migrated = 0;
	int nr_max_tries = min(rq->nr_running, SCHED_RQ_NR_MIGRATION);
	struct skiplist_node *node = rq->sl_header.next[0];

	while (nr_max_tries && node != &rq->sl_header) {
		struct task_struct *p;

		/* seek to the next node */
		node = node->next[0];
		if (node == &rq->sl_header)
			break;

		p = skiplist_entry(node, struct task_struct, sl_node);
		node = node->next[0];
		nr_max_tries--;

		/* skip the running task and check CPU affinity */
		if (!task_running(p) &&
		    cpumask_test_cpu(dest_cpu, &p->cpus_allowed)) {
			detach_task(rq, p, dest_cpu);
			attach_task(cpu_rq(dest_cpu), p);
			nr_migrated++;
		}
	}

	return nr_migrated;
}

static inline struct task_struct *
take_queued_task_cpumask(int cpu, struct cpumask *chk_mask)
{
	int src_cpu;

	for_each_cpu(src_cpu, chk_mask) {
		int nr_migrated;
		struct rq *src_rq = cpu_rq(src_cpu);

		raw_spin_lock_nested(&src_rq->lock, SINGLE_DEPTH_NESTING);
		update_rq_clock(src_rq);
		nr_migrated = migrate_pending_tasks(src_rq, cpu);
		raw_spin_unlock(&src_rq->lock);

		if (nr_migrated)
			return rq_first_queued_task(cpu_rq(cpu));
	}
	return NULL;
}

static inline struct task_struct *take_other_rq_task(int cpu)
{
	struct cpumask tmp;
	struct cpumask *affinity_mask, *end;

	if (0 == sched_nr_rq_pending)
		return NULL;

	if (1 == sched_nr_rq_pending)
		return take_queued_task_cpumask(cpu, &sched_rq_pending_mask);

	affinity_mask = &(per_cpu(sched_cpu_affinity_chk_masks, cpu)[0]);
	end = per_cpu(sched_cpu_affinity_chk_end_masks, cpu);
	for (;affinity_mask < end; affinity_mask++) {
		struct task_struct *p;
		if (cpumask_and(&tmp, &sched_rq_pending_mask, affinity_mask) &&
		    (p = take_queued_task_cpumask(cpu, &tmp)))
			return p;
	}

	return NULL;
}
#endif

static inline struct task_struct *choose_next_task(struct rq *rq, int cpu)
{
	struct task_struct *next;

	if ((next = rq_first_queued_task(rq)))
		return next;

#ifdef	CONFIG_SMP
	if (likely(rq->online))
		if ((next = take_other_rq_task(cpu)))
			return next;
#endif
	return rq->idle;
}

static inline unsigned long get_preempt_disable_ip(struct task_struct *p)
{
#ifdef CONFIG_DEBUG_PREEMPT
	return p->preempt_disable_ip;
#else
	return 0;
#endif
}

/*
 * Print scheduling while atomic bug:
 */
static noinline void __schedule_bug(struct task_struct *prev)
{
	/* Save this before calling printk(), since that will clobber it */
	unsigned long preempt_disable_ip = get_preempt_disable_ip(current);

	if (oops_in_progress)
		return;

	printk(KERN_ERR "BUG: scheduling while atomic: %s/%d/0x%08x\n",
		prev->comm, prev->pid, preempt_count());

	debug_show_held_locks(prev);
	print_modules();
	if (irqs_disabled())
		print_irqtrace_events(prev);
	if (IS_ENABLED(CONFIG_DEBUG_PREEMPT)
	    && in_atomic_preempt_off()) {
		pr_err("Preemption disabled at:");
		print_ip_sym(preempt_disable_ip);
		pr_cont("\n");
	}
	if (panic_on_warn)
		panic("scheduling while atomic\n");

	dump_stack();
	add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
}

/*
 * Various schedule()-time debugging checks and statistics:
 */
static inline void schedule_debug(struct task_struct *prev)
{
#ifdef CONFIG_SCHED_STACK_END_CHECK
	if (task_stack_end_corrupted(prev))
		panic("corrupted stack end detected inside scheduler\n");
#endif

	if (unlikely(in_atomic_preempt_off())) {
		__schedule_bug(prev);
		preempt_count_set(PREEMPT_DISABLED);
	}
	rcu_sleep_check();

	profile_hit(SCHED_PROFILING, __builtin_return_address(0));

	schedstat_inc(this_rq()->sched_count);
}

static inline void set_rq_task(struct rq *rq, struct task_struct *p)
{
	p->last_ran = rq->clock_task;

#ifdef CONFIG_HIGH_RES_TIMERS
	if (!(p == rq->idle || p->policy == SCHED_FIFO))
		hrtick_start(rq, US_TO_NS(p->time_slice));
#endif
	/* update rq->dither */
	rq->dither = rq_dither(rq);
}

/*
 * schedule() is the main scheduler function.
 *
 * The main means of driving the scheduler and thus entering this function are:
 *
 *   1. Explicit blocking: mutex, semaphore, waitqueue, etc.
 *
 *   2. TIF_NEED_RESCHED flag is checked on interrupt and userspace return
 *      paths. For example, see arch/x86/entry_64.S.
 *
 *      To drive preemption between tasks, the scheduler sets the flag in timer
 *      interrupt handler scheduler_tick().
 *
 *   3. Wakeups don't really cause entry into schedule(). They add a
 *      task to the run-queue and that's it.
 *
 *      Now, if the new task added to the run-queue preempts the current
 *      task, then the wakeup sets TIF_NEED_RESCHED and schedule() gets
 *      called on the nearest possible occasion:
 *
 *       - If the kernel is preemptible (CONFIG_PREEMPT=y):
 *
 *         - in syscall or exception context, at the next outmost
 *           preempt_enable(). (this might be as soon as the wake_up()'s
 *           spin_unlock()!)
 *
 *         - in IRQ context, return from interrupt-handler to
 *           preemptible context
 *
 *       - If the kernel is not preemptible (CONFIG_PREEMPT is not set)
 *         then at the next:
 *
 *          - cond_resched() call
 *          - explicit schedule() call
 *          - return from syscall or exception to user-space
 *          - return from interrupt-handler to user-space
 *
 * WARNING: must be called with preemption disabled!
 */
static void __sched notrace __schedule(bool preempt)
{
	struct task_struct *prev, *next;
	unsigned long *switch_count;
	struct rq *rq;
	int cpu;

	cpu = smp_processor_id();
	rq = cpu_rq(cpu);
	prev = rq->curr;

	schedule_debug(prev);

	/* by passing sched_feat(HRTICK) checking which PDS doesn't support */
	hrtick_clear(rq);

	local_irq_disable();
	rcu_note_context_switch(preempt);

	/*
	 * Make sure that signal_pending_state()->signal_pending() below
	 * can't be reordered with __set_current_state(TASK_INTERRUPTIBLE)
	 * done by the caller to avoid the race with signal_wake_up().
	 *
	 * The membarrier system call requires a full memory barrier
	 * after coming from user-space, before storing to rq->curr.
	 */
	raw_spin_lock(&rq->lock);
	smp_mb__after_spinlock();

	update_rq_clock(rq);

	switch_count = &prev->nivcsw;
	if (!preempt && prev->state) {
		if (unlikely(signal_pending_state(prev->state, prev))) {
			prev->state = TASK_RUNNING;
		} else {
			deactivate_task(prev, rq);

			if (prev->in_iowait) {
				atomic_inc(&rq->nr_iowait);
				delayacct_blkio_start();
			}

			/*
			 * If a worker is going to sleep, notify and
			 * ask workqueue whether it wants to wake up a
			 * task to maintain concurrency.  If so, wake
			 * up the task.
			 */
			if (prev->flags & PF_WQ_WORKER) {
				struct task_struct *to_wakeup;

				to_wakeup = wq_worker_sleeping(prev);
				if (to_wakeup)
					try_to_wake_up_local(to_wakeup);
			}
		}
		switch_count = &prev->nvcsw;
	}

	clear_tsk_need_resched(prev);
	clear_preempt_need_resched();

	check_deadline(prev, rq);

	next = choose_next_task(rq, cpu);

	set_rq_task(rq, next);

	if (prev != next) {
#ifdef CONFIG_SCHED_SMT
		cpumask_clear_cpu(cpu, &sched_cpu_sb_suppress_mask);
#endif
		if (next->prio == PRIO_LIMIT)
			schedstat_inc(rq->sched_goidle);

		rq->curr = next;
		/*
		 * The membarrier system call requires each architecture
		 * to have a full memory barrier after updating
		 * rq->curr, before returning to user-space.
		 *
		 * Here are the schemes providing that barrier on the
		 * various architectures:
		 * - mm ? switch_mm() : mmdrop() for x86, s390, sparc, PowerPC.
		 *   switch_mm() rely on membarrier_arch_switch_mm() on PowerPC.
		 * - finish_lock_switch() for weakly-ordered
		 *   architectures where spin_unlock is a full barrier,
		 * - switch_to() for arm64 (weakly-ordered, spin_unlock
		 *   is a RELEASE barrier),
		 */
		++*switch_count;
		rq->nr_switches++;

		trace_sched_switch(preempt, prev, next);

		/* Also unlocks the rq: */
		rq = context_switch(rq, prev, next);
		cpu = cpu_of(rq);
	} else
		raw_spin_unlock_irq(&rq->lock);
}

void __noreturn do_task_dead(void)
{
	/* Causes final put_task_struct in finish_task_switch(): */
	set_special_state(TASK_DEAD);

	/* Tell freezer to ignore us: */
	current->flags |= PF_NOFREEZE;
	__schedule(false);

	BUG();

	/* Avoid "noreturn function does return" - but don't continue if BUG() is a NOP: */
	for (;;)
		cpu_relax();
}

static inline void sched_submit_work(struct task_struct *tsk)
{
	if (!tsk->state || tsk_is_pi_blocked(tsk) ||
	    signal_pending_state(tsk->state, tsk))
		return;

	/*
	 * If we are going to sleep and we have plugged IO queued,
	 * make sure to submit it to avoid deadlocks.
	 */
	if (blk_needs_flush_plug(tsk))
		blk_schedule_flush_plug(tsk);
}

asmlinkage __visible void __sched schedule(void)
{
	struct task_struct *tsk = current;

	sched_submit_work(tsk);
	do {
		preempt_disable();
		__schedule(false);
		sched_preempt_enable_no_resched();
	} while (need_resched());
}
EXPORT_SYMBOL(schedule);

/*
 * synchronize_rcu_tasks() makes sure that no task is stuck in preempted
 * state (have scheduled out non-voluntarily) by making sure that all
 * tasks have either left the run queue or have gone into user space.
 * As idle tasks do not do either, they must not ever be preempted
 * (schedule out non-voluntarily).
 *
 * schedule_idle() is similar to schedule_preempt_disable() except that it
 * never enables preemption because it does not call sched_submit_work().
 */
void __sched schedule_idle(void)
{
	/*
	 * As this skips calling sched_submit_work(), which the idle task does
	 * regardless because that function is a nop when the task is in a
	 * TASK_RUNNING state, make sure this isn't used someplace that the
	 * current task can be in any other state. Note, idle is always in the
	 * TASK_RUNNING state.
	 */
	WARN_ON_ONCE(current->state);
	do {
		__schedule(false);
	} while (need_resched());
}

#ifdef CONFIG_CONTEXT_TRACKING
asmlinkage __visible void __sched schedule_user(void)
{
	/*
	 * If we come here after a random call to set_need_resched(),
	 * or we have been woken up remotely but the IPI has not yet arrived,
	 * we haven't yet exited the RCU idle mode. Do it here manually until
	 * we find a better solution.
	 *
	 * NB: There are buggy callers of this function.  Ideally we
	 * should warn if prev_state != CONTEXT_USER, but that will trigger
	 * too frequently to make sense yet.
	 */
	enum ctx_state prev_state = exception_enter();
	schedule();
	exception_exit(prev_state);
}
#endif

/**
 * schedule_preempt_disabled - called with preemption disabled
 *
 * Returns with preemption disabled. Note: preempt_count must be 1
 */
void __sched schedule_preempt_disabled(void)
{
	sched_preempt_enable_no_resched();
	schedule();
	preempt_disable();
}

static void __sched notrace preempt_schedule_common(void)
{
	do {
		/*
		 * Because the function tracer can trace preempt_count_sub()
		 * and it also uses preempt_enable/disable_notrace(), if
		 * NEED_RESCHED is set, the preempt_enable_notrace() called
		 * by the function tracer will call this function again and
		 * cause infinite recursion.
		 *
		 * Preemption must be disabled here before the function
		 * tracer can trace. Break up preempt_disable() into two
		 * calls. One to disable preemption without fear of being
		 * traced. The other to still record the preemption latency,
		 * which can also be traced by the function tracer.
		 */
		preempt_disable_notrace();
		preempt_latency_start(1);
		__schedule(true);
		preempt_latency_stop(1);
		preempt_enable_no_resched_notrace();

		/*
		 * Check again in case we missed a preemption opportunity
		 * between schedule and now.
		 */
	} while (need_resched());
}

#ifdef CONFIG_PREEMPT
/*
 * this is the entry point to schedule() from in-kernel preemption
 * off of preempt_enable. Kernel preemptions off return from interrupt
 * occur there and call schedule directly.
 */
asmlinkage __visible void __sched notrace preempt_schedule(void)
{
	/*
	 * If there is a non-zero preempt_count or interrupts are disabled,
	 * we do not want to preempt the current task. Just return..
	 */
	if (likely(!preemptible()))
		return;

	preempt_schedule_common();
}
NOKPROBE_SYMBOL(preempt_schedule);
EXPORT_SYMBOL(preempt_schedule);

/**
 * preempt_schedule_notrace - preempt_schedule called by tracing
 *
 * The tracing infrastructure uses preempt_enable_notrace to prevent
 * recursion and tracing preempt enabling caused by the tracing
 * infrastructure itself. But as tracing can happen in areas coming
 * from userspace or just about to enter userspace, a preempt enable
 * can occur before user_exit() is called. This will cause the scheduler
 * to be called when the system is still in usermode.
 *
 * To prevent this, the preempt_enable_notrace will use this function
 * instead of preempt_schedule() to exit user context if needed before
 * calling the scheduler.
 */
asmlinkage __visible void __sched notrace preempt_schedule_notrace(void)
{
	enum ctx_state prev_ctx;

	if (likely(!preemptible()))
		return;

	do {
		/*
		 * Because the function tracer can trace preempt_count_sub()
		 * and it also uses preempt_enable/disable_notrace(), if
		 * NEED_RESCHED is set, the preempt_enable_notrace() called
		 * by the function tracer will call this function again and
		 * cause infinite recursion.
		 *
		 * Preemption must be disabled here before the function
		 * tracer can trace. Break up preempt_disable() into two
		 * calls. One to disable preemption without fear of being
		 * traced. The other to still record the preemption latency,
		 * which can also be traced by the function tracer.
		 */
		preempt_disable_notrace();
		preempt_latency_start(1);
		/*
		 * Needs preempt disabled in case user_exit() is traced
		 * and the tracer calls preempt_enable_notrace() causing
		 * an infinite recursion.
		 */
		prev_ctx = exception_enter();
		__schedule(true);
		exception_exit(prev_ctx);

		preempt_latency_stop(1);
		preempt_enable_no_resched_notrace();
	} while (need_resched());
}
EXPORT_SYMBOL_GPL(preempt_schedule_notrace);

#endif /* CONFIG_PREEMPT */

/*
 * this is the entry point to schedule() from kernel preemption
 * off of irq context.
 * Note, that this is called and return with irqs disabled. This will
 * protect us against recursive calling from irq.
 */
asmlinkage __visible void __sched preempt_schedule_irq(void)
{
	enum ctx_state prev_state;

	/* Catch callers which need to be fixed */
	BUG_ON(preempt_count() || !irqs_disabled());

	prev_state = exception_enter();

	do {
		preempt_disable();
		local_irq_enable();
		__schedule(true);
		local_irq_disable();
		sched_preempt_enable_no_resched();
	} while (need_resched());

	exception_exit(prev_state);
}

int default_wake_function(wait_queue_entry_t *curr, unsigned mode, int wake_flags,
			  void *key)
{
	return try_to_wake_up(curr->private, mode, wake_flags);
}
EXPORT_SYMBOL(default_wake_function);

static inline void
check_task_changed(struct rq *rq, struct task_struct *p)
{
	/*
	 * Trigger changes when task priority/deadline modified.
	 */
	if (task_queued(p)) {
		struct task_struct *first;

		requeue_task(p, rq);

		/* Resched if first queued task not running and not IDLE */
		if ((first = rq_first_queued_task(rq)) != rq->curr &&
		    !task_running_idle(first))
			resched_curr(rq);
	}
}

#ifdef CONFIG_RT_MUTEXES

static inline int __rt_effective_prio(struct task_struct *pi_task, int prio)
{
	if (pi_task)
		prio = min(prio, pi_task->prio);

	return prio;
}

static inline int rt_effective_prio(struct task_struct *p, int prio)
{
	struct task_struct *pi_task = rt_mutex_get_top_task(p);

	return __rt_effective_prio(pi_task, prio);
}

/*
 * rt_mutex_setprio - set the current priority of a task
 * @p: task to boost
 * @pi_task: donor task
 *
 * This function changes the 'effective' priority of a task. It does
 * not touch ->normal_prio like __setscheduler().
 *
 * Used by the rt_mutex code to implement priority inheritance
 * logic. Call site only calls if the priority of the task changed.
 */
void rt_mutex_setprio(struct task_struct *p, struct task_struct *pi_task)
{
	int prio;
	struct rq *rq;
	raw_spinlock_t *lock;

	/* XXX used to be waiter->prio, not waiter->task->prio */
	prio = __rt_effective_prio(pi_task, p->normal_prio);

	/*
	 * If nothing changed; bail early.
	 */
	if (p->pi_top_task == pi_task && prio == p->prio)
		return;

	rq = __task_access_lock(p, &lock);
	/*
	 * Set under pi_lock && rq->lock, such that the value can be used under
	 * either lock.
	 *
	 * Note that there is loads of tricky to make this pointer cache work
	 * right. rt_mutex_slowunlock()+rt_mutex_postunlock() work together to
	 * ensure a task is de-boosted (pi_task is set to NULL) before the
	 * task is allowed to run again (and can exit). This ensures the pointer
	 * points to a blocked task -- which guaratees the task is present.
	 */
	p->pi_top_task = pi_task;

	/*
	 * For FIFO/RR we only need to set prio, if that matches we're done.
	 */
	if (prio == p->prio)
		goto out_unlock;

	/*
	 * Idle task boosting is a nono in general. There is one
	 * exception, when PREEMPT_RT and NOHZ is active:
	 *
	 * The idle task calls get_next_timer_interrupt() and holds
	 * the timer wheel base->lock on the CPU and another CPU wants
	 * to access the timer (probably to cancel it). We can safely
	 * ignore the boosting request, as the idle CPU runs this code
	 * with interrupts disabled and will complete the lock
	 * protected section without being interrupted. So there is no
	 * real need to boost.
	 */
	if (unlikely(p == rq->idle)) {
		WARN_ON(p != rq->curr);
		WARN_ON(p->pi_blocked_on);
		goto out_unlock;
	}

	trace_sched_pi_setprio(p, pi_task);
	p->prio = prio;
	update_task_priodl(p);

	check_task_changed(rq, p);

out_unlock:
	__task_access_unlock(p, lock);
}
#else
static inline int rt_effective_prio(struct task_struct *p, int prio)
{
	return prio;
}
#endif

void set_user_nice(struct task_struct *p, long nice)
{
	int new_static;
	unsigned long flags;
	struct rq *rq;
	raw_spinlock_t *lock;

	if (task_nice(p) == nice || nice < MIN_NICE || nice > MAX_NICE)
		return;
	new_static = NICE_TO_PRIO(nice);
	/*
	 * We have to be careful, if called from sys_setpriority(),
	 * the task might be in the middle of scheduling on another CPU.
	 */
	raw_spin_lock_irqsave(&p->pi_lock, flags);
	rq = __task_access_lock(p, &lock);

	/* rq lock may not held!! */
	update_rq_clock(rq);
	/*
	 * The RT priorities are set via sched_setscheduler(), but we still
	 * allow the 'normal' nice value to be set - but as expected
	 * it wont have any effect on scheduling until the task is
	 * not SCHED_NORMAL/SCHED_BATCH:
	 */
	if (has_rt_policy(p)) {
		p->static_prio = new_static;
		goto out_unlock;
	}

	p->deadline -= task_deadline_diff(p);
	p->deadline += static_deadline_diff(new_static);
	p->static_prio = new_static;
	p->prio = effective_prio(p);
	update_task_priodl(p);

	check_task_changed(rq, p);
out_unlock:
	__task_access_unlock(p, lock);
	raw_spin_unlock_irqrestore(&p->pi_lock, flags);
}
EXPORT_SYMBOL(set_user_nice);

/*
 * can_nice - check if a task can reduce its nice value
 * @p: task
 * @nice: nice value
 */
int can_nice(const struct task_struct *p, const int nice)
{
	/* Convert nice value [19,-20] to rlimit style value [1,40] */
	int nice_rlim = nice_to_rlimit(nice);

	return (nice_rlim <= task_rlimit(p, RLIMIT_NICE) ||
		capable(CAP_SYS_NICE));
}

#ifdef __ARCH_WANT_SYS_NICE

/*
 * sys_nice - change the priority of the current process.
 * @increment: priority increment
 *
 * sys_setpriority is a more generic, but much slower function that
 * does similar things.
 */
SYSCALL_DEFINE1(nice, int, increment)
{
	long nice, retval;

	/*
	 * Setpriority might change our priority at the same moment.
	 * We don't have to worry. Conceptually one call occurs first
	 * and we have a single winner.
	 */

	increment = clamp(increment, -NICE_WIDTH, NICE_WIDTH);
	nice = task_nice(current) + increment;

	nice = clamp_val(nice, MIN_NICE, MAX_NICE);
	if (increment < 0 && !can_nice(current, nice))
		return -EPERM;

	retval = security_task_setnice(current, nice);
	if (retval)
		return retval;

	set_user_nice(current, nice);
	return 0;
}

#endif

/**
 * task_prio - return the priority value of a given task.
 * @p: the task in question.
 *
 * Return: The priority value as seen by users in /proc.
 * RT tasks are offset by -100. Normal tasks are centered around 1, value goes
 * from 0 (SCHED_ISO) up to 82 (nice +19 SCHED_IDLE).
 */
int task_prio(const struct task_struct *p)
{
	int level, prio = p->prio - MAX_RT_PRIO;
	static const int level_to_nice_prio[] = {39, 33, 26, 20, 14, 7, 0, 0};

	/* rt tasks and iso tasks */
	if (prio <= 0)
		goto out;

	preempt_disable();
	level = task_deadline_level(p, this_rq());
	preempt_enable();
	prio += level_to_nice_prio[level];
	if (idleprio_task(p))
		prio += NICE_WIDTH;
out:
	return prio;
}

/**
 * idle_cpu - is a given CPU idle currently?
 * @cpu: the processor in question.
 *
 * Return: 1 if the CPU is currently idle. 0 otherwise.
 */
int idle_cpu(int cpu)
{
	return cpu_curr(cpu) == cpu_rq(cpu)->idle;
}

/**
 * idle_task - return the idle task for a given CPU.
 * @cpu: the processor in question.
 *
 * Return: The idle task for the cpu @cpu.
 */
struct task_struct *idle_task(int cpu)
{
	return cpu_rq(cpu)->idle;
}

/**
 * find_process_by_pid - find a process with a matching PID value.
 * @pid: the pid in question.
 *
 * The task of @pid, if found. %NULL otherwise.
 */
static inline struct task_struct *find_process_by_pid(pid_t pid)
{
	return pid ? find_task_by_vpid(pid) : current;
}

#ifdef CONFIG_SMP
void sched_set_stop_task(int cpu, struct task_struct *stop)
{
	struct sched_param stop_param = { .sched_priority = STOP_PRIO };
	struct sched_param start_param = { .sched_priority = 0 };
	struct task_struct *old_stop = cpu_rq(cpu)->stop;

	if (stop) {
		/*
		 * Make it appear like a SCHED_FIFO task, its something
		 * userspace knows about and won't get confused about.
		 *
		 * Also, it will make PI more or less work without too
		 * much confusion -- but then, stop work should not
		 * rely on PI working anyway.
		 */
		sched_setscheduler_nocheck(stop, SCHED_FIFO, &stop_param);
	}

	cpu_rq(cpu)->stop = stop;

	if (old_stop) {
		/*
		 * Reset it back to a normal scheduling policy so that
		 * it can die in pieces.
		 */
		sched_setscheduler_nocheck(old_stop, SCHED_NORMAL, &start_param);
	}
}

/*
 * Change a given task's CPU affinity. Migrate the thread to a
 * proper CPU and schedule it away if the CPU it's executing on
 * is removed from the allowed bitmask.
 *
 * NOTE: the caller must have a valid reference to the task, the
 * task must not exit() & deallocate itself prematurely. The
 * call is not atomic; no spinlocks may be held.
 */
static int __set_cpus_allowed_ptr(struct task_struct *p,
				  const struct cpumask *new_mask, bool check)
{
	const struct cpumask *cpu_valid_mask = cpu_active_mask;
	int dest_cpu;
	bool queued = false;
	unsigned long flags;
	struct rq *rq;
	raw_spinlock_t *lock;
	int ret = 0;

	raw_spin_lock_irqsave(&p->pi_lock, flags);
	rq = __task_access_lock(p, &lock);

	if (p->flags & PF_KTHREAD) {
		/*
		 * Kernel threads are allowed on online && !active CPUs
		 */
		cpu_valid_mask = cpu_online_mask;
	}

	/*
	 * Must re-check here, to close a race against __kthread_bind(),
	 * sched_setaffinity() is not guaranteed to observe the flag.
	 */
	if (check && (p->flags & PF_NO_SETAFFINITY)) {
		ret = -EINVAL;
		goto out;
	}

	if (cpumask_equal(&p->cpus_allowed, new_mask))
		goto out;

	if (!cpumask_intersects(new_mask, cpu_valid_mask)) {
		ret = -EINVAL;
		goto out;
	}

	queued = task_queued(p);

	do_set_cpus_allowed(p, new_mask);

	if (p->flags & PF_KTHREAD) {
		/*
		 * For kernel threads that do indeed end up on online &&
		 * !active we want to ensure they are strict per-CPU threads.
		 */
		WARN_ON(cpumask_intersects(new_mask, cpu_online_mask) &&
			!cpumask_intersects(new_mask, cpu_active_mask) &&
			p->nr_cpus_allowed != 1);
	}

	/* Can the task run on the task's current CPU? If so, we're done */
	if (cpumask_test_cpu(task_cpu(p), new_mask))
		goto out;

	dest_cpu = cpumask_any_and(cpu_valid_mask, new_mask);
	if (task_running(p) || p->state == TASK_WAKING) {
		struct migration_arg arg = { p, dest_cpu };

		/* Need help from migration thread: drop lock and wait. */
		__task_access_unlock(p, lock);
		raw_spin_unlock_irqrestore(&p->pi_lock, flags);
		stop_one_cpu(cpu_of(rq), migration_cpu_stop, &arg);
		tlb_migrate_finish(p->mm);
		return 0;
	}
	if (task_queued(p)) {
		/*
		 * OK, since we're going to drop the lock immediately
		 * afterwards anyway.
		 */
		update_rq_clock(rq);
		rq = move_queued_task(rq, p, dest_cpu);
		lock = &rq->lock;
	}

out:
	__task_access_unlock(p, lock);
	raw_spin_unlock_irqrestore(&p->pi_lock, flags);

	return ret;
}

int set_cpus_allowed_ptr(struct task_struct *p, const struct cpumask *new_mask)
{
	return __set_cpus_allowed_ptr(p, new_mask, false);
}
EXPORT_SYMBOL_GPL(set_cpus_allowed_ptr);

#else
static inline int
__set_cpus_allowed_ptr(struct task_struct *p,
		       const struct cpumask *new_mask, bool check)
{
	return set_cpus_allowed_ptr(p, new_mask);
}
#endif

static u64 task_init_deadline(const struct task_struct *p)
{
	return task_rq(p)->clock + task_deadline_diff(p);
}

u64 (* task_init_deadline_func_tbl[])(const struct task_struct *p) = {
	task_init_deadline,	/* SCHED_NORMAL */
	NULL,			/* SCHED_FIFO */
	NULL,			/* SCHED_RR */
	task_init_deadline,	/* SCHED_BATCH */
	NULL,			/* SCHED_ISO */
	task_init_deadline	/* SCHED_IDLE */
};

/*
 * sched_setparam() passes in -1 for its policy, to let the functions
 * it calls know not to change it.
 */
#define SETPARAM_POLICY -1

static void __setscheduler_params(struct task_struct *p,
		const struct sched_attr *attr)
{
	int old_policy = p->policy;
	int policy = attr->sched_policy;

	if (policy == SETPARAM_POLICY)
		policy = p->policy;

	p->policy = policy;

	/*
	 * allow normal nice value to be set, but will not have any
	 * effect on scheduling until the task not SCHED_NORMAL/
	 * SCHED_BATCH
	 */
	p->static_prio = NICE_TO_PRIO(attr->sched_nice);

	/*
	 * __sched_setscheduler() ensures attr->sched_priority == 0 when
	 * !rt_policy. Always setting this ensures that things like
	 * getparam()/getattr() don't report silly values for !rt tasks.
	 */
	p->rt_priority = attr->sched_priority;
	p->normal_prio = normal_prio(p);

	if (old_policy != policy)
		p->deadline = (task_init_deadline_func_tbl[p->policy])?
			task_init_deadline_func_tbl[p->policy](p):0ULL;
}

/* Actually do priority change: must hold rq lock. */
static void __setscheduler(struct rq *rq, struct task_struct *p,
			   const struct sched_attr *attr, bool keep_boost)
{
	__setscheduler_params(p, attr);

	/*
	 * Keep a potential priority boosting if called from
	 * sched_setscheduler().
	 */
	if (keep_boost)
		p->prio = rt_effective_prio(p, p->prio);
	update_task_priodl(p);
}

/*
 * check the target process has a UID that matches the current process's
 */
static bool check_same_owner(struct task_struct *p)
{
	const struct cred *cred = current_cred(), *pcred;
	bool match;

	rcu_read_lock();
	pcred = __task_cred(p);
	match = (uid_eq(cred->euid, pcred->euid) ||
		 uid_eq(cred->euid, pcred->uid));
	rcu_read_unlock();
	return match;
}

static int
__sched_setscheduler(struct task_struct *p,
		     const struct sched_attr *attr, bool user, bool pi)
{
	int newprio = MAX_RT_PRIO - 1 - attr->sched_priority;
	int retval, oldpolicy = -1;
	int policy = attr->sched_policy;
	unsigned long flags;
	struct rq *rq;
	int reset_on_fork;
	raw_spinlock_t *lock;

	/* The pi code expects interrupts enabled */
	BUG_ON(pi && in_interrupt());
recheck:
	/* Double check policy once rq lock held */
	if (policy < 0) {
		reset_on_fork = p->sched_reset_on_fork;
		policy = oldpolicy = p->policy;
	} else {
		reset_on_fork = !!(attr->sched_flags & SCHED_RESET_ON_FORK);

		if (policy > SCHED_IDLE)
			return -EINVAL;
	}

	if (attr->sched_flags & ~(SCHED_FLAG_RESET_ON_FORK))
		return -EINVAL;

	/*
	 * Valid priorities for SCHED_FIFO and SCHED_RR are
	 * 1..MAX_USER_RT_PRIO-1, valid priority for SCHED_NORMAL and
	 * SCHED_BATCH and SCHED_IDLE is 0.
	 */
	if (attr->sched_priority < 0 ||
	    (p->mm && attr->sched_priority > MAX_USER_RT_PRIO - 1) ||
	    (!p->mm && attr->sched_priority > MAX_RT_PRIO - 1))
		return -EINVAL;
	if (is_rt_policy(policy) != (attr->sched_priority != 0))
		return -EINVAL;

	/*
	 * Allow unprivileged RT tasks to decrease priority:
	 */
	if (user && !capable(CAP_SYS_NICE)) {
		if (is_rt_policy(policy)) {
			unsigned long rlim_rtprio =
					task_rlimit(p, RLIMIT_RTPRIO);

			/* Can't set/change the rt policy */
			if (policy != p->policy && !rlim_rtprio)
				return -EPERM;

			/* Can't increase priority */
			if (attr->sched_priority > p->rt_priority &&
			    attr->sched_priority > rlim_rtprio)
				return -EPERM;
		} else {
			switch (p->policy) {
				/*
				 * Can only downgrade policies but not back to
				 * SCHED_NORMAL
				 */
				case SCHED_ISO:
					if (policy == SCHED_ISO)
						return 0;
					if (policy == SCHED_NORMAL)
						return -EPERM;
					break;
				case SCHED_BATCH:
					if (policy == SCHED_BATCH)
						return 0;
					if (policy != SCHED_IDLE)
						return -EPERM;
					break;
				case SCHED_IDLE:
					if (policy == SCHED_IDLE)
						return 0;
					return -EPERM;
				default:
					break;
			}
		}

		/* Can't change other user's priorities */
		if (!check_same_owner(p))
			return -EPERM;

		/* Normal users shall not reset the sched_reset_on_fork flag */
		if (p->sched_reset_on_fork && !reset_on_fork)
			return -EPERM;
	}

	if (user) {
		retval = security_task_setscheduler(p);
		if (retval)
			return retval;
	}

	/*
	 * make sure no PI-waiters arrive (or leave) while we are
	 * changing the priority of the task:
	 */
	raw_spin_lock_irqsave(&p->pi_lock, flags);

	/*
	 * To be able to change p->policy safely, task_access_lock()
	 * must be called.
	 * IF use task_access_lock() here:
	 * For the task p which is not running, reading rq->stop is
	 * racy but acceptable as ->stop doesn't change much.
	 * An enhancemnet can be made to read rq->stop saftly.
	 */
	rq = __task_access_lock(p, &lock);

	/*
	 * Changing the policy of the stop threads its a very bad idea
	 */
	if (p == rq->stop) {
		__task_access_unlock(p, lock);
		raw_spin_unlock_irqrestore(&p->pi_lock, flags);
		return -EINVAL;
	}

	/*
	 * If not changing anything there's no need to proceed further:
	 */
	if (unlikely(policy == p->policy && (!is_rt_policy(policy) ||
		attr->sched_priority == p->rt_priority))) {
		p->sched_reset_on_fork = reset_on_fork;
		__task_access_unlock(p, lock);
		raw_spin_unlock_irqrestore(&p->pi_lock, flags);
		return 0;
	}

	/* Re-check policy now with rq lock held */
	if (unlikely(oldpolicy != -1 && oldpolicy != p->policy)) {
		policy = oldpolicy = -1;
		__task_access_unlock(p, lock);
		raw_spin_unlock_irqrestore(&p->pi_lock, flags);
		goto recheck;
	}

	p->sched_reset_on_fork = reset_on_fork;

	if (pi) {
		/*
		 * Take priority boosted tasks into account. If the new
		 * effective priority is unchanged, we just store the new
		 * normal parameters and do not touch the scheduler class and
		 * the runqueue. This will be done when the task deboost
		 * itself.
		 */
		if (rt_effective_prio(p, newprio) == p->prio) {
			__setscheduler_params(p, attr);
			__task_access_unlock(p, lock);
			raw_spin_unlock_irqrestore(&p->pi_lock, flags);
			return 0;
		}
	}

	__setscheduler(rq, p, attr, pi);

	check_task_changed(rq, p);

	/* Avoid rq from going away on us: */
	preempt_disable();
	__task_access_unlock(p, lock);
	raw_spin_unlock_irqrestore(&p->pi_lock, flags);

	if (pi)
		rt_mutex_adjust_pi(p);

	preempt_enable();

	return 0;
}

static int _sched_setscheduler(struct task_struct *p, int policy,
			       const struct sched_param *param, bool check)
{
	struct sched_attr attr = {
		.sched_policy   = policy,
		.sched_priority = param->sched_priority,
		.sched_nice     = PRIO_TO_NICE(p->static_prio),
	};
	unsigned long rlim_rtprio = 0;

	/* Fixup the legacy SCHED_RESET_ON_FORK hack. */
	if ((policy != SETPARAM_POLICY) && (policy & SCHED_RESET_ON_FORK)) {
		attr.sched_flags |= SCHED_FLAG_RESET_ON_FORK;
		policy &= ~SCHED_RESET_ON_FORK;
		attr.sched_policy = policy;
	}

	if (is_rt_policy(policy) && !capable(CAP_SYS_NICE)) {
		unsigned long lflags;

		if (!lock_task_sighand(p, &lflags))
			return -ESRCH;
		rlim_rtprio = task_rlimit(p, RLIMIT_RTPRIO);
		unlock_task_sighand(p, &lflags);
		if (!rlim_rtprio) {
			/*
			 * If the caller requested an RT policy without having the
			 * necessary rights, we downgrade the policy to SCHED_ISO.
			 * We also set the attr to zero to pass the checks.
			 */
			attr.sched_policy = SCHED_ISO;
			attr.sched_priority = 0;
			attr.sched_nice = 0;
		}
	}

	return __sched_setscheduler(p, &attr, check, true);
}

/**
 * sched_setscheduler - change the scheduling policy and/or RT priority of a thread.
 * @p: the task in question.
 * @policy: new policy.
 * @param: structure containing the new RT priority.
 *
 * Return: 0 on success. An error code otherwise.
 *
 * NOTE that the task may be already dead.
 */
int sched_setscheduler(struct task_struct *p, int policy,
		       const struct sched_param *param)
{
	return _sched_setscheduler(p, policy, param, true);
}

EXPORT_SYMBOL_GPL(sched_setscheduler);

int sched_setattr(struct task_struct *p, const struct sched_attr *attr)
{
	return __sched_setscheduler(p, attr, true, true);
}
EXPORT_SYMBOL_GPL(sched_setattr);

/**
 * sched_setscheduler_nocheck - change the scheduling policy and/or RT priority of a thread from kernelspace.
 * @p: the task in question.
 * @policy: new policy.
 * @param: structure containing the new RT priority.
 *
 * Just like sched_setscheduler, only don't bother checking if the
 * current context has permission.  For example, this is needed in
 * stop_machine(): we create temporary high priority worker threads,
 * but our caller might not have that capability.
 *
 * Return: 0 on success. An error code otherwise.
 */
int sched_setscheduler_nocheck(struct task_struct *p, int policy,
			       const struct sched_param *param)
{
	return _sched_setscheduler(p, policy, param, false);
}
EXPORT_SYMBOL_GPL(sched_setscheduler_nocheck);

static int
do_sched_setscheduler(pid_t pid, int policy, struct sched_param __user *param)
{
	struct sched_param lparam;
	struct task_struct *p;
	int retval;

	if (!param || pid < 0)
		return -EINVAL;
	if (copy_from_user(&lparam, param, sizeof(struct sched_param)))
		return -EFAULT;

	rcu_read_lock();
	retval = -ESRCH;
	p = find_process_by_pid(pid);
	if (p != NULL)
		retval = sched_setscheduler(p, policy, &lparam);
	rcu_read_unlock();

	return retval;
}

/*
 * Mimics kernel/events/core.c perf_copy_attr().
 */
static int sched_copy_attr(struct sched_attr __user *uattr, struct sched_attr *attr)
{
	u32 size;
	int ret;

	if (!access_ok(VERIFY_WRITE, uattr, SCHED_ATTR_SIZE_VER0))
		return -EFAULT;

	/* Zero the full structure, so that a short copy will be nice: */
	memset(attr, 0, sizeof(*attr));

	ret = get_user(size, &uattr->size);
	if (ret)
		return ret;

	/* Bail out on silly large: */
	if (size > PAGE_SIZE)
		goto err_size;

	/* ABI compatibility quirk: */
	if (!size)
		size = SCHED_ATTR_SIZE_VER0;

	if (size < SCHED_ATTR_SIZE_VER0)
		goto err_size;

	/*
	 * If we're handed a bigger struct than we know of,
	 * ensure all the unknown bits are 0 - i.e. new
	 * user-space does not rely on any kernel feature
	 * extensions we dont know about yet.
	 */
	if (size > sizeof(*attr)) {
		unsigned char __user *addr;
		unsigned char __user *end;
		unsigned char val;

		addr = (void __user *)uattr + sizeof(*attr);
		end  = (void __user *)uattr + size;

		for (; addr < end; addr++) {
			ret = get_user(val, addr);
			if (ret)
				return ret;
			if (val)
				goto err_size;
		}
		size = sizeof(*attr);
	}

	ret = copy_from_user(attr, uattr, size);
	if (ret)
		return -EFAULT;

	/*
	 * XXX: Do we want to be lenient like existing syscalls; or do we want
	 * to be strict and return an error on out-of-bounds values?
	 */
	attr->sched_nice = clamp(attr->sched_nice, -20, 19);

	/* sched/core.c uses zero here but we already know ret is zero */
	return 0;

err_size:
	put_user(sizeof(*attr), &uattr->size);
	return -E2BIG;
}

/**
 * sys_sched_setscheduler - set/change the scheduler policy and RT priority
 * @pid: the pid in question.
 * @policy: new policy.
 *
 * Return: 0 on success. An error code otherwise.
 * @param: structure containing the new RT priority.
 */
SYSCALL_DEFINE3(sched_setscheduler, pid_t, pid, int, policy, struct sched_param __user *, param)
{
	if (policy < 0)
		return -EINVAL;

	return do_sched_setscheduler(pid, policy, param);
}

/**
 * sys_sched_setparam - set/change the RT priority of a thread
 * @pid: the pid in question.
 * @param: structure containing the new RT priority.
 *
 * Return: 0 on success. An error code otherwise.
 */
SYSCALL_DEFINE2(sched_setparam, pid_t, pid, struct sched_param __user *, param)
{
	return do_sched_setscheduler(pid, SETPARAM_POLICY, param);
}

/**
 * sys_sched_setattr - same as above, but with extended sched_attr
 * @pid: the pid in question.
 * @uattr: structure containing the extended parameters.
 */
SYSCALL_DEFINE3(sched_setattr, pid_t, pid, struct sched_attr __user *, uattr,
			       unsigned int, flags)
{
	struct sched_attr attr;
	struct task_struct *p;
	int retval;

	if (!uattr || pid < 0 || flags)
		return -EINVAL;

	retval = sched_copy_attr(uattr, &attr);
	if (retval)
		return retval;

	if ((int)attr.sched_policy < 0)
		return -EINVAL;

	rcu_read_lock();
	retval = -ESRCH;
	p = find_process_by_pid(pid);
	if (p != NULL)
		retval = sched_setattr(p, &attr);
	rcu_read_unlock();

	return retval;
}

/**
 * sys_sched_getscheduler - get the policy (scheduling class) of a thread
 * @pid: the pid in question.
 *
 * Return: On success, the policy of the thread. Otherwise, a negative error
 * code.
 */
SYSCALL_DEFINE1(sched_getscheduler, pid_t, pid)
{
	struct task_struct *p;
	int retval = -EINVAL;

	if (pid < 0)
		goto out_nounlock;

	retval = -ESRCH;
	rcu_read_lock();
	p = find_process_by_pid(pid);
	if (p) {
		retval = security_task_getscheduler(p);
		if (!retval)
			retval = p->policy;
	}
	rcu_read_unlock();

out_nounlock:
	return retval;
}

/**
 * sys_sched_getscheduler - get the RT priority of a thread
 * @pid: the pid in question.
 * @param: structure containing the RT priority.
 *
 * Return: On success, 0 and the RT priority is in @param. Otherwise, an error
 * code.
 */
SYSCALL_DEFINE2(sched_getparam, pid_t, pid, struct sched_param __user *, param)
{
	struct sched_param lp = { .sched_priority = 0 };
	struct task_struct *p;
	int retval = -EINVAL;

	if (!param || pid < 0)
		goto out_nounlock;

	rcu_read_lock();
	p = find_process_by_pid(pid);
	retval = -ESRCH;
	if (!p)
		goto out_unlock;

	retval = security_task_getscheduler(p);
	if (retval)
		goto out_unlock;

	if (has_rt_policy(p))
		lp.sched_priority = p->rt_priority;
	rcu_read_unlock();

	/*
	 * This one might sleep, we cannot do it with a spinlock held ...
	 */
	retval = copy_to_user(param, &lp, sizeof(*param)) ? -EFAULT : 0;

out_nounlock:
	return retval;

out_unlock:
	rcu_read_unlock();
	return retval;
}

static int sched_read_attr(struct sched_attr __user *uattr,
			   struct sched_attr *attr,
			   unsigned int usize)
{
	int ret;

	if (!access_ok(VERIFY_WRITE, uattr, usize))
		return -EFAULT;

	/*
	 * If we're handed a smaller struct than we know of,
	 * ensure all the unknown bits are 0 - i.e. old
	 * user-space does not get uncomplete information.
	 */
	if (usize < sizeof(*attr)) {
		unsigned char *addr;
		unsigned char *end;

		addr = (void *)attr + usize;
		end  = (void *)attr + sizeof(*attr);

		for (; addr < end; addr++) {
			if (*addr)
				return -EFBIG;
		}

		attr->size = usize;
	}

	ret = copy_to_user(uattr, attr, attr->size);
	if (ret)
		return -EFAULT;

	/* sched/core.c uses zero here but we already know ret is zero */
	return ret;
}

/**
 * sys_sched_getattr - similar to sched_getparam, but with sched_attr
 * @pid: the pid in question.
 * @uattr: structure containing the extended parameters.
 * @size: sizeof(attr) for fwd/bwd comp.
 * @flags: for future extension.
 */
SYSCALL_DEFINE4(sched_getattr, pid_t, pid, struct sched_attr __user *, uattr,
		unsigned int, size, unsigned int, flags)
{
	struct sched_attr attr = {
		.size = sizeof(struct sched_attr),
	};
	struct task_struct *p;
	int retval;

	if (!uattr || pid < 0 || size > PAGE_SIZE ||
	    size < SCHED_ATTR_SIZE_VER0 || flags)
		return -EINVAL;

	rcu_read_lock();
	p = find_process_by_pid(pid);
	retval = -ESRCH;
	if (!p)
		goto out_unlock;

	retval = security_task_getscheduler(p);
	if (retval)
		goto out_unlock;

	attr.sched_policy = p->policy;
	if (rt_task(p))
		attr.sched_priority = p->rt_priority;
	else
		attr.sched_nice = task_nice(p);

	rcu_read_unlock();

	retval = sched_read_attr(uattr, &attr, size);
	return retval;

out_unlock:
	rcu_read_unlock();
	return retval;
}

long sched_setaffinity(pid_t pid, const struct cpumask *in_mask)
{
	cpumask_var_t cpus_allowed, new_mask;
	struct task_struct *p;
	int retval;

	get_online_cpus();
	rcu_read_lock();

	p = find_process_by_pid(pid);
	if (!p) {
		rcu_read_unlock();
		put_online_cpus();
		return -ESRCH;
	}

	/* Prevent p going away */
	get_task_struct(p);
	rcu_read_unlock();

	if (p->flags & PF_NO_SETAFFINITY) {
		retval = -EINVAL;
		goto out_put_task;
	}
	if (!alloc_cpumask_var(&cpus_allowed, GFP_KERNEL)) {
		retval = -ENOMEM;
		goto out_put_task;
	}
	if (!alloc_cpumask_var(&new_mask, GFP_KERNEL)) {
		retval = -ENOMEM;
		goto out_free_cpus_allowed;
	}
	retval = -EPERM;
	if (!check_same_owner(p)) {
		rcu_read_lock();
		if (!ns_capable(__task_cred(p)->user_ns, CAP_SYS_NICE)) {
			rcu_read_unlock();
			goto out_unlock;
		}
		rcu_read_unlock();
	}

	retval = security_task_setscheduler(p);
	if (retval)
		goto out_unlock;

	cpuset_cpus_allowed(p, cpus_allowed);
	cpumask_and(new_mask, in_mask, cpus_allowed);
again:
	retval = __set_cpus_allowed_ptr(p, new_mask, true);

	if (!retval) {
		cpuset_cpus_allowed(p, cpus_allowed);
		if (!cpumask_subset(new_mask, cpus_allowed)) {
			/*
			 * We must have raced with a concurrent cpuset
			 * update. Just reset the cpus_allowed to the
			 * cpuset's cpus_allowed
			 */
			cpumask_copy(new_mask, cpus_allowed);
			goto again;
		}
	}
out_unlock:
	free_cpumask_var(new_mask);
out_free_cpus_allowed:
	free_cpumask_var(cpus_allowed);
out_put_task:
	put_task_struct(p);
	put_online_cpus();
	return retval;
}

static int get_user_cpu_mask(unsigned long __user *user_mask_ptr, unsigned len,
			     struct cpumask *new_mask)
{
	if (len < cpumask_size())
		cpumask_clear(new_mask);
	else if (len > cpumask_size())
		len = cpumask_size();

	return copy_from_user(new_mask, user_mask_ptr, len) ? -EFAULT : 0;
}

/**
 * sys_sched_setaffinity - set the CPU affinity of a process
 * @pid: pid of the process
 * @len: length in bytes of the bitmask pointed to by user_mask_ptr
 * @user_mask_ptr: user-space pointer to the new CPU mask
 *
 * Return: 0 on success. An error code otherwise.
 */
SYSCALL_DEFINE3(sched_setaffinity, pid_t, pid, unsigned int, len,
		unsigned long __user *, user_mask_ptr)
{
	cpumask_var_t new_mask;
	int retval;

	if (!alloc_cpumask_var(&new_mask, GFP_KERNEL))
		return -ENOMEM;

	retval = get_user_cpu_mask(user_mask_ptr, len, new_mask);
	if (retval == 0)
		retval = sched_setaffinity(pid, new_mask);
	free_cpumask_var(new_mask);
	return retval;
}

long sched_getaffinity(pid_t pid, cpumask_t *mask)
{
	struct task_struct *p;
	raw_spinlock_t *lock;
	unsigned long flags;
	int retval;

	rcu_read_lock();

	retval = -ESRCH;
	p = find_process_by_pid(pid);
	if (!p)
		goto out_unlock;

	retval = security_task_getscheduler(p);
	if (retval)
		goto out_unlock;

	task_access_lock_irqsave(p, &lock, &flags);
	cpumask_and(mask, &p->cpus_allowed, cpu_active_mask);
	task_access_unlock_irqrestore(p, lock, &flags);

out_unlock:
	rcu_read_unlock();

	return retval;
}

/**
 * sys_sched_getaffinity - get the CPU affinity of a process
 * @pid: pid of the process
 * @len: length in bytes of the bitmask pointed to by user_mask_ptr
 * @user_mask_ptr: user-space pointer to hold the current CPU mask
 *
 * Return: size of CPU mask copied to user_mask_ptr on success. An
 * error code otherwise.
 */
SYSCALL_DEFINE3(sched_getaffinity, pid_t, pid, unsigned int, len,
		unsigned long __user *, user_mask_ptr)
{
	int ret;
	cpumask_var_t mask;

	if ((len * BITS_PER_BYTE) < nr_cpu_ids)
		return -EINVAL;
	if (len & (sizeof(unsigned long)-1))
		return -EINVAL;

	if (!alloc_cpumask_var(&mask, GFP_KERNEL))
		return -ENOMEM;

	ret = sched_getaffinity(pid, mask);
	if (ret == 0) {
		unsigned int retlen = min_t(size_t, len, cpumask_size());

		if (copy_to_user(user_mask_ptr, mask, retlen))
			ret = -EFAULT;
		else
			ret = retlen;
	}
	free_cpumask_var(mask);

	return ret;
}

/**
 * sys_sched_yield - yield the current processor to other threads.
 *
 * This function yields the current CPU to other tasks. It does this by
 * scheduling away the current task. If it still has the earliest deadline
 * it will be scheduled again as the next task.
 *
 * Return: 0.
 */
static void do_sched_yield(void)
{
	struct rq *rq;

	if (!sched_yield_type)
		return;

	local_irq_disable();
	rq = this_rq();
	raw_spin_lock(&rq->lock);

	if (sched_yield_type > 1) {
		time_slice_expired(current, rq);
		requeue_task(current, rq);
	}
	schedstat_inc(rq->yld_count);

	/*
	 * Since we are going to call schedule() anyway, there's
	 * no need to preempt or enable interrupts:
	 */
	preempt_disable();
	raw_spin_unlock(&rq->lock);
	sched_preempt_enable_no_resched();

	schedule();
}

SYSCALL_DEFINE0(sched_yield)
{
	do_sched_yield();
	return 0;
}

#ifndef CONFIG_PREEMPT
int __sched _cond_resched(void)
{
	if (should_resched(0)) {
		preempt_schedule_common();
		return 1;
	}
	rcu_all_qs();
	return 0;
}
EXPORT_SYMBOL(_cond_resched);
#endif

/*
 * __cond_resched_lock() - if a reschedule is pending, drop the given lock,
 * call schedule, and on return reacquire the lock.
 *
 * This works OK both with and without CONFIG_PREEMPT.  We do strange low-level
 * operations here to prevent schedule() from being called twice (once via
 * spin_unlock(), once by hand).
 */
int __cond_resched_lock(spinlock_t *lock)
{
	int resched = should_resched(PREEMPT_LOCK_OFFSET);
	int ret = 0;

	lockdep_assert_held(lock);

	if (spin_needbreak(lock) || resched) {
		spin_unlock(lock);
		if (resched)
			preempt_schedule_common();
		else
			cpu_relax();
		ret = 1;
		spin_lock(lock);
	}
	return ret;
}
EXPORT_SYMBOL(__cond_resched_lock);

int __sched __cond_resched_softirq(void)
{
	BUG_ON(!in_softirq());

	if (should_resched(SOFTIRQ_DISABLE_OFFSET)) {
		local_bh_enable();
		preempt_schedule_common();
		local_bh_disable();
		return 1;
	}
	return 0;
}
EXPORT_SYMBOL(__cond_resched_softirq);

/**
 * yield - yield the current processor to other threads.
 *
 * Do not ever use this function, there's a 99% chance you're doing it wrong.
 *
 * The scheduler is at all times free to pick the calling task as the most
 * eligible task to run, if removing the yield() call from your code breaks
 * it, its already broken.
 *
 * Typical broken usage is:
 *
 * while (!event)
 * 	yield();
 *
 * where one assumes that yield() will let 'the other' process run that will
 * make event true. If the current task is a SCHED_FIFO task that will never
 * happen. Never use yield() as a progress guarantee!!
 *
 * If you want to use yield() to wait for something, use wait_event().
 * If you want to use yield() to be 'nice' for others, use cond_resched().
 * If you still want to use yield(), do not!
 */
void __sched yield(void)
{
	set_current_state(TASK_RUNNING);
	do_sched_yield();
}
EXPORT_SYMBOL(yield);

/**
 * yield_to - yield the current processor to another thread in
 * your thread group, or accelerate that thread toward the
 * processor it's on.
 * @p: target task
 * @preempt: whether task preemption is allowed or not
 *
 * It's the caller's job to ensure that the target task struct
 * can't go away on us before we can do any checks.
 *
 * In PDS, yield_to is not supported.
 *
 * Return:
 *	true (>0) if we indeed boosted the target task.
 *	false (0) if we failed to boost the target.
 *	-ESRCH if there's no task to yield to.
 */
int __sched yield_to(struct task_struct *p, bool preempt)
{
	return 0;
}
EXPORT_SYMBOL_GPL(yield_to);

int io_schedule_prepare(void)
{
	int old_iowait = current->in_iowait;

	current->in_iowait = 1;
	blk_schedule_flush_plug(current);

	return old_iowait;
}

void io_schedule_finish(int token)
{
	current->in_iowait = token;
}

/*
 * This task is about to go to sleep on IO.  Increment rq->nr_iowait so
 * that process accounting knows that this is a task in IO wait state.
 *
 * But don't do that if it is a deliberate, throttling IO wait (this task
 * has set its backing_dev_info: the queue against which it should throttle)
 */

long __sched io_schedule_timeout(long timeout)
{
	int token;
	long ret;

	token = io_schedule_prepare();
	ret = schedule_timeout(timeout);
	io_schedule_finish(token);

	return ret;
}
EXPORT_SYMBOL(io_schedule_timeout);

void io_schedule(void)
{
	int token;

	token = io_schedule_prepare();
	schedule();
	io_schedule_finish(token);
}
EXPORT_SYMBOL(io_schedule);

/**
 * sys_sched_get_priority_max - return maximum RT priority.
 * @policy: scheduling class.
 *
 * Return: On success, this syscall returns the maximum
 * rt_priority that can be used by a given scheduling class.
 * On failure, a negative error code is returned.
 */
SYSCALL_DEFINE1(sched_get_priority_max, int, policy)
{
	int ret = -EINVAL;

	switch (policy) {
	case SCHED_FIFO:
	case SCHED_RR:
		ret = MAX_USER_RT_PRIO-1;
		break;
	case SCHED_NORMAL:
	case SCHED_BATCH:
	case SCHED_ISO:
	case SCHED_IDLE:
		ret = 0;
		break;
	}
	return ret;
}

/**
 * sys_sched_get_priority_min - return minimum RT priority.
 * @policy: scheduling class.
 *
 * Return: On success, this syscall returns the minimum
 * rt_priority that can be used by a given scheduling class.
 * On failure, a negative error code is returned.
 */
SYSCALL_DEFINE1(sched_get_priority_min, int, policy)
{
	int ret = -EINVAL;

	switch (policy) {
	case SCHED_FIFO:
	case SCHED_RR:
		ret = 1;
		break;
	case SCHED_NORMAL:
	case SCHED_BATCH:
	case SCHED_ISO:
	case SCHED_IDLE:
		ret = 0;
		break;
	}
	return ret;
}

static int sched_rr_get_interval(pid_t pid, struct timespec64 *t)
{
	struct task_struct *p;
	unsigned int time_slice;
	unsigned long flags;
	int retval;
	raw_spinlock_t *lock;

	if (pid < 0)
		return -EINVAL;

	retval = -ESRCH;
	rcu_read_lock();
	p = find_process_by_pid(pid);
	if (!p)
		goto out_unlock;

	retval = security_task_getscheduler(p);
	if (retval)
		goto out_unlock;

	task_access_lock_irqsave(p, &lock, &flags);
	time_slice = p->policy == SCHED_FIFO ? 0 : MS_TO_NS(rr_interval);
	task_access_unlock_irqrestore(p, lock, &flags);

	rcu_read_unlock();
	*t = ns_to_timespec64(time_slice);
	return 0;

out_unlock:
	rcu_read_unlock();
	return retval;
}

/**
 * sys_sched_rr_get_interval - return the default timeslice of a process.
 * @pid: pid of the process.
 * @interval: userspace pointer to the timeslice value.
 *
 *
 * Return: On success, 0 and the timeslice is in @interval. Otherwise,
 * an error code.
 */
SYSCALL_DEFINE2(sched_rr_get_interval, pid_t, pid,
		struct timespec __user *, interval)
{
	struct timespec64 t;
	int retval = sched_rr_get_interval(pid, &t);

	if (retval == 0)
		retval = put_timespec64(&t, interval);

	return retval;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE2(sched_rr_get_interval,
		       compat_pid_t, pid,
		       struct compat_timespec __user *, interval)
{
	struct timespec64 t;
	int retval = sched_rr_get_interval(pid, &t);

	if (retval == 0)
		retval = compat_put_timespec64(&t, interval);
	return retval;
}
#endif

void sched_show_task(struct task_struct *p)
{
	unsigned long free = 0;
	int ppid;

	if (!try_get_task_stack(p))
		return;

	printk(KERN_INFO "%-15.15s %c", p->comm, task_state_to_char(p));

	if (p->state == TASK_RUNNING)
		printk(KERN_CONT "  running task    ");
#ifdef CONFIG_DEBUG_STACK_USAGE
	free = stack_not_used(p);
#endif
	ppid = 0;
	rcu_read_lock();
	if (pid_alive(p))
		ppid = task_pid_nr(rcu_dereference(p->real_parent));
	rcu_read_unlock();
	printk(KERN_CONT "%5lu %5d %6d 0x%08lx\n", free,
		task_pid_nr(p), ppid,
		(unsigned long)task_thread_info(p)->flags);

	print_worker_info(KERN_INFO, p);
	show_stack(p, NULL);
	put_task_stack(p);
}
EXPORT_SYMBOL_GPL(sched_show_task);

static inline bool
state_filter_match(unsigned long state_filter, struct task_struct *p)
{
	/* no filter, everything matches */
	if (!state_filter)
		return true;

	/* filter, but doesn't match */
	if (!(p->state & state_filter))
		return false;

	/*
	 * When looking for TASK_UNINTERRUPTIBLE skip TASK_IDLE (allows
	 * TASK_KILLABLE).
	 */
	if (state_filter == TASK_UNINTERRUPTIBLE && p->state == TASK_IDLE)
		return false;

	return true;
}


void show_state_filter(unsigned long state_filter)
{
	struct task_struct *g, *p;

#if BITS_PER_LONG == 32
	printk(KERN_INFO
		"  task                PC stack   pid father\n");
#else
	printk(KERN_INFO
		"  task                        PC stack   pid father\n");
#endif
	rcu_read_lock();
	for_each_process_thread(g, p) {
		/*
		 * reset the NMI-timeout, listing all files on a slow
		 * console might take a lot of time:
		 * Also, reset softlockup watchdogs on all CPUs, because
		 * another CPU might be blocked waiting for us to process
		 * an IPI.
		 */
		touch_nmi_watchdog();
		touch_all_softlockup_watchdogs();
		if (state_filter_match(state_filter, p))
			sched_show_task(p);
	}

#ifdef CONFIG_SCHED_DEBUG
	/* PDS TODO: should support this
	if (!state_filter)
		sysrq_sched_debug_show();
	*/
#endif
	rcu_read_unlock();
	/*
	 * Only show locks if all tasks are dumped:
	 */
	if (!state_filter)
		debug_show_all_locks();
}

void dump_cpu_task(int cpu)
{
	pr_info("Task dump for CPU %d:\n", cpu);
	sched_show_task(cpu_curr(cpu));
}

/**
 * init_idle - set up an idle thread for a given CPU
 * @idle: task in question
 * @cpu: cpu the idle task belongs to
 *
 * NOTE: this function does not set the idle thread's NEED_RESCHED
 * flag, to make booting more robust.
 */
void init_idle(struct task_struct *idle, int cpu)
{
	struct rq *rq = cpu_rq(cpu);
	unsigned long flags;

	raw_spin_lock_irqsave(&idle->pi_lock, flags);
	raw_spin_lock(&rq->lock);
	update_rq_clock(rq);

	idle->last_ran = rq->clock_task;
	idle->state = TASK_RUNNING;
	idle->flags |= PF_IDLE;
	/* Setting prio to illegal value shouldn't matter when never queued */
	idle->prio = PRIO_LIMIT;
	idle->deadline = rq_clock(rq) + task_deadline_diff(idle);
	update_task_priodl(idle);

	kasan_unpoison_task_stack(idle);

#ifdef CONFIG_SMP
	/*
	 * It's possible that init_idle() gets called multiple times on a task,
	 * in that case do_set_cpus_allowed() will not do the right thing.
	 *
	 * And since this is boot we can forgo the serialisation.
	 */
	set_cpus_allowed_common(idle, cpumask_of(cpu));
#endif

	/* Silence PROVE_RCU */
	rcu_read_lock();
	__set_task_cpu(idle, cpu);
	rcu_read_unlock();

	rq->curr = rq->idle = idle;
	idle->on_cpu = 1;

	raw_spin_unlock(&rq->lock);
	raw_spin_unlock_irqrestore(&idle->pi_lock, flags);

	/* Set the preempt count _outside_ the spinlocks! */
	init_idle_preempt_count(idle, cpu);

	ftrace_graph_init_idle_task(idle, cpu);
	vtime_init_idle(idle, cpu);
#ifdef CONFIG_SMP
	sprintf(idle->comm, "%s/%d", INIT_TASK_COMM, cpu);
#endif
}

void resched_cpu(int cpu)
{
	struct rq *rq = cpu_rq(cpu);
	unsigned long flags;

	raw_spin_lock_irqsave(&rq->lock, flags);
	if (cpu_online(cpu) || cpu == smp_processor_id())
		resched_curr(cpu_rq(cpu));
	raw_spin_unlock_irqrestore(&rq->lock, flags);
}

void wake_q_add(struct wake_q_head *head, struct task_struct *task)
{
	struct wake_q_node *node = &task->wake_q;

	/*
	 * Atomically grab the task, if ->wake_q is !nil already it means
	 * its already queued (either by us or someone else) and will get the
	 * wakeup due to that.
	 *
	 * This cmpxchg() implies a full barrier, which pairs with the write
	 * barrier implied by the wakeup in wake_up_q().
	 */
	if (cmpxchg(&node->next, NULL, WAKE_Q_TAIL))
		return;

	get_task_struct(task);

	/*
	 * The head is context local, there can be no concurrency.
	 */
	*head->lastp = node;
	head->lastp = &node->next;
}

void wake_up_q(struct wake_q_head *head)
{
	struct wake_q_node *node = head->first;

	while (node != WAKE_Q_TAIL) {
		struct task_struct *task;

		task = container_of(node, struct task_struct, wake_q);
		BUG_ON(!task);
		/* task can safely be re-inserted now: */
		node = node->next;
		task->wake_q.next = NULL;

		/*
		 * wake_up_process() implies a wmb() to pair with the queueing
		 * in wake_q_add() so as not to miss wakeups.
		 */
		wake_up_process(task);
		put_task_struct(task);
	}
}

#ifdef CONFIG_SMP

int cpuset_cpumask_can_shrink(const struct cpumask __maybe_unused *cur,
			      const struct cpumask __maybe_unused *trial)
{
	return 1;
}

int task_can_attach(struct task_struct *p,
		    const struct cpumask *cs_cpus_allowed)
{
	int ret = 0;

	/*
	 * Kthreads which disallow setaffinity shouldn't be moved
	 * to a new cpuset; we don't want to change their CPU
	 * affinity and isolating such threads by their set of
	 * allowed nodes is unnecessary.  Thus, cpusets are not
	 * applicable for such threads.  This prevents checking for
	 * success of set_cpus_allowed_ptr() on all attached tasks
	 * before cpus_allowed may be changed.
	 */
	if (p->flags & PF_NO_SETAFFINITY)
		ret = -EINVAL;

	return ret;
}

static bool sched_smp_initialized __read_mostly;

#ifdef CONFIG_NO_HZ_COMMON
void nohz_balance_enter_idle(int cpu)
{
}

void select_nohz_load_balancer(int stop_tick)
{
}

void set_cpu_sd_state_idle(void) {}

/*
 * In the semi idle case, use the nearest busy CPU for migrating timers
 * from an idle CPU.  This is good for power-savings.
 *
 * We don't do similar optimization for completely idle system, as
 * selecting an idle CPU will add more delays to the timers than intended
 * (as that CPU's timer base may not be uptodate wrt jiffies etc).
 */
int get_nohz_timer_target(void)
{
	int i, cpu = smp_processor_id();
	struct cpumask *mask;

	if (!idle_cpu(cpu) && housekeeping_cpu(cpu, HK_FLAG_TIMER))
		return cpu;

	for (mask = &(per_cpu(sched_cpu_affinity_chk_masks, cpu)[0]);
	     mask < per_cpu(sched_cpu_affinity_chk_end_masks, cpu); mask++)
		for_each_cpu(i, mask)
			if (!idle_cpu(i) && housekeeping_cpu(i, HK_FLAG_TIMER))
				return i;

	if (!housekeeping_cpu(cpu, HK_FLAG_TIMER))
		cpu = housekeeping_any_cpu(HK_FLAG_TIMER);

	return cpu;
}

/*
 * When add_timer_on() enqueues a timer into the timer wheel of an
 * idle CPU then this timer might expire before the next timer event
 * which is scheduled to wake up that CPU. In case of a completely
 * idle system the next event might even be infinite time into the
 * future. wake_up_idle_cpu() ensures that the CPU is woken up and
 * leaves the inner idle loop so the newly added timer is taken into
 * account when the CPU goes back to idle and evaluates the timer
 * wheel for the next timer event.
 */
void wake_up_idle_cpu(int cpu)
{
	if (cpu == smp_processor_id())
		return;

	set_tsk_need_resched(cpu_rq(cpu)->idle);
	smp_send_reschedule(cpu);
}

void wake_up_nohz_cpu(int cpu)
{
	wake_up_idle_cpu(cpu);
}
#endif /* CONFIG_NO_HZ_COMMON */

#ifdef CONFIG_HOTPLUG_CPU
/*
 * Ensures that the idle task is using init_mm right before its CPU goes
 * offline.
 */
void idle_task_exit(void)
{
	struct mm_struct *mm = current->active_mm;

	BUG_ON(cpu_online(smp_processor_id()));

	if (mm != &init_mm) {
		switch_mm(mm, &init_mm, current);
		current->active_mm = &init_mm;
		finish_arch_post_lock_switch();
	}
	mmdrop(mm);
}

/*
 * Migrate all tasks from the rq, sleeping tasks will be migrated by
 * try_to_wake_up()->select_task_rq().
 *
 * Called with rq->lock held even though we'er in stop_machine() and
 * there's no concurrency possible, we hold the required locks anyway
 * because of lock validation efforts.
 */
static void migrate_tasks(struct rq *dead_rq)
{
	struct rq *rq = dead_rq;
	struct task_struct *p, *stop = rq->stop;
	struct skiplist_node *node;
	int count = 0;

	/*
	 * Fudge the rq selection such that the below task selection loop
	 * doesn't get stuck on the currently eligible stop task.
	 *
	 * We're currently inside stop_machine() and the rq is either stuck
	 * in the stop_machine_cpu_stop() loop, or we're executing this code,
	 * either way we should never end up calling schedule() until we're
	 * done here.
	 */
	rq->stop = NULL;

	node = &rq->sl_header;
	while ((node = node->next[0]) != &rq->sl_header) {
		int dest_cpu;

		p = skiplist_entry(node, struct task_struct, sl_node);

		/* Leave kernel tasks only on this CPU along: */
		if (p->flags & PF_KTHREAD && p->nr_cpus_allowed == 1)
			continue;

		/*
		 * Rules for changing task_struct::cpus_allowed are holding
		 * both pi_lock and rq->lock, such that holding either
		 * stabilizes the mask.
		 *
		 * Drop rq->lock is not quite as disastrous as it usually is
		 * because !cpu_active at this point, which means load-balance
		 * will not interfere. Also, stop-machine.
		 */
		raw_spin_unlock(&rq->lock);
		raw_spin_lock(&p->pi_lock);
		raw_spin_lock(&rq->lock);

		/*
		 * Since we're inside stop-machine, _nothing_ should have
		 * changed the task, WARN if weird stuff happened, because in
		 * that case the above rq->lock drop is a fail too.
		 */
		if (WARN_ON(task_rq(p) != rq || !task_queued(p))) {
			raw_spin_unlock(&p->pi_lock);
			continue;
		}

		count++;
		if (!cpumask_intersects(&p->cpus_allowed, cpu_online_mask))
			cpumask_set_cpu(0, &p->cpus_allowed);
		p->nr_cpus_allowed = cpumask_weight(&p->cpus_allowed);
		dest_cpu = cpumask_any_and(&p->cpus_allowed, cpu_online_mask);

		rq = __migrate_task(rq, p, dest_cpu);
		raw_spin_unlock(&rq->lock);
		raw_spin_unlock(&p->pi_lock);

		rq = dead_rq;
		raw_spin_lock(&rq->lock);
		/* Check queued task all over from the header again */
		node = &rq->sl_header;
	}

	rq->stop = stop;
}

static void set_rq_offline(struct rq *rq)
{
	if (rq->online)
		rq->online = false;
}
#endif /* CONFIG_HOTPLUG_CPU */

static void set_rq_online(struct rq *rq)
{
	if (!rq->online)
		rq->online = true;
}

#ifdef CONFIG_SCHED_DEBUG

static __read_mostly int sched_debug_enabled;

static int __init sched_debug_setup(char *str)
{
	sched_debug_enabled = 1;

	return 0;
}
early_param("sched_debug", sched_debug_setup);

static inline bool sched_debug(void)
{
	return sched_debug_enabled;
}
#else /* !CONFIG_SCHED_DEBUG */
static inline bool sched_debug(void)
{
	return false;
}
#endif /* CONFIG_SCHED_DEBUG */

#ifdef CONFIG_SMP
void scheduler_ipi(void)
{
	/*
	 * Fold TIF_NEED_RESCHED into the preempt_count; anybody setting
	 * TIF_NEED_RESCHED remotely (for the first time) will also send
	 * this IPI.
	 */
	preempt_fold_need_resched();

	if (!idle_cpu(smp_processor_id()) || need_resched())
		return;

	irq_enter();
	irq_exit();
}

void wake_up_if_idle(int cpu)
{
	struct rq *rq = cpu_rq(cpu);
	unsigned long flags;

	rcu_read_lock();

	if (!is_idle_task(rcu_dereference(rq->curr)))
		goto out;

	if (set_nr_if_polling(rq->idle)) {
		trace_sched_wake_idle_without_ipi(cpu);
	} else {
		raw_spin_lock_irqsave(&rq->lock, flags);
		if (is_idle_task(rq->curr))
			smp_send_reschedule(cpu);
		/* Else CPU is not idle, do nothing here */
		raw_spin_unlock_irqrestore(&rq->lock, flags);
	}

out:
	rcu_read_unlock();
}

bool cpus_share_cache(int this_cpu, int that_cpu)
{
	return per_cpu(sd_llc_id, this_cpu) == per_cpu(sd_llc_id, that_cpu);
}
#endif /* CONFIG_SMP */

/*
 * Topology list, bottom-up.
 */
static struct sched_domain_topology_level default_topology[] = {
#ifdef CONFIG_SCHED_SMT
	{ cpu_smt_mask, cpu_smt_flags, SD_INIT_NAME(SMT) },
#endif
#ifdef CONFIG_SCHED_MC
	{ cpu_coregroup_mask, cpu_core_flags, SD_INIT_NAME(MC) },
#endif
	{ cpu_cpu_mask, SD_INIT_NAME(DIE) },
	{ NULL, },
};

static struct sched_domain_topology_level *sched_domain_topology =
	default_topology;

#define for_each_sd_topology(tl)			\
	for (tl = sched_domain_topology; tl->mask; tl++)

void set_sched_topology(struct sched_domain_topology_level *tl)
{
	if (WARN_ON_ONCE(sched_smp_initialized))
		return;

	sched_domain_topology = tl;
}

/*
 * Initializers for schedule domains
 * Non-inlined to reduce accumulated stack pressure in build_sched_domains()
 */

int sched_domain_level_max;

/*
 * Partition sched domains as specified by the 'ndoms_new'
 * cpumasks in the array doms_new[] of cpumasks. This compares
 * doms_new[] to the current sched domain partitioning, doms_cur[].
 * It destroys each deleted domain and builds each new domain.
 *
 * 'doms_new' is an array of cpumask_var_t's of length 'ndoms_new'.
 * The masks don't intersect (don't overlap.) We should setup one
 * sched domain for each mask. CPUs not in any of the cpumasks will
 * not be load balanced. If the same cpumask appears both in the
 * current 'doms_cur' domains and in the new 'doms_new', we can leave
 * it as it is.
 *
 * The passed in 'doms_new' should be allocated using
 * alloc_sched_domains.  This routine takes ownership of it and will
 * free_sched_domains it when done with it. If the caller failed the
 * alloc call, then it can pass in doms_new == NULL && ndoms_new == 1,
 * and partition_sched_domains() will fallback to the single partition
 * 'fallback_doms', it also forces the domains to be rebuilt.
 *
 * If doms_new == NULL it will be replaced with cpu_online_mask.
 * ndoms_new == 0 is a special case for destroying existing domains,
 * and it will not create the default domain.
 *
 * Call with hotplug lock held
 */
void partition_sched_domains(int ndoms_new, cpumask_var_t doms_new[],
			     struct sched_domain_attr *dattr_new)
{
	/**
	 * PDS doesn't depend on sched domains, but just keep this api
	 */
}

/*
 * used to mark begin/end of suspend/resume:
 */
static int num_cpus_frozen;

/*
 * Update cpusets according to cpu_active mask.  If cpusets are
 * disabled, cpuset_update_active_cpus() becomes a simple wrapper
 * around partition_sched_domains().
 *
 * If we come here as part of a suspend/resume, don't touch cpusets because we
 * want to restore it back to its original state upon resume anyway.
 */
static void cpuset_cpu_active(void)
{
	if (cpuhp_tasks_frozen) {
		/*
		 * num_cpus_frozen tracks how many CPUs are involved in suspend
		 * resume sequence. As long as this is not the last online
		 * operation in the resume sequence, just build a single sched
		 * domain, ignoring cpusets.
		 */
		partition_sched_domains(1, NULL, NULL);
		if (--num_cpus_frozen)
			return;
		/*
		 * This is the last CPU online operation. So fall through and
		 * restore the original sched domains by considering the
		 * cpuset configurations.
		 */
		cpuset_force_rebuild();
	}

	cpuset_update_active_cpus();
}

static int cpuset_cpu_inactive(unsigned int cpu)
{
	if (!cpuhp_tasks_frozen) {
		cpuset_update_active_cpus();
	} else {
		num_cpus_frozen++;
		partition_sched_domains(1, NULL, NULL);
	}
	return 0;
}

int sched_cpu_activate(unsigned int cpu)
{
	struct rq *rq = cpu_rq(cpu);
	unsigned long flags;

	set_cpu_active(cpu, true);

	if (sched_smp_initialized)
		cpuset_cpu_active();

	/*
	 * Put the rq online, if not already. This happens:
	 *
	 * 1) In the early boot process, because we build the real domains
	 *    after all cpus have been brought up.
	 *
	 * 2) At runtime, if cpuset_cpu_active() fails to rebuild the
	 *    domains.
	 */
	raw_spin_lock_irqsave(&rq->lock, flags);
	set_rq_online(rq);
	raw_spin_unlock_irqrestore(&rq->lock, flags);

	return 0;
}

int sched_cpu_deactivate(unsigned int cpu)
{
	int ret;

	set_cpu_active(cpu, false);
	/*
	 * We've cleared cpu_active_mask, wait for all preempt-disabled and RCU
	 * users of this state to go away such that all new such users will
	 * observe it.
	 *
	 * Do sync before park smpboot threads to take care the rcu boost case.
	 */
	synchronize_rcu_mult(call_rcu, call_rcu_sched);

	if (!sched_smp_initialized)
		return 0;

	ret = cpuset_cpu_inactive(cpu);
	if (ret) {
		set_cpu_active(cpu, true);
		return ret;
	}
	return 0;
}

static void sched_rq_cpu_starting(unsigned int cpu)
{
	struct rq *rq = cpu_rq(cpu);

	rq->calc_load_update = calc_load_update;
}

int sched_cpu_starting(unsigned int cpu)
{
	/*
	 * PDS doesn't have rq start time record
	 * set_cpu_rq_start_time(cpu);
	 */
	sched_rq_cpu_starting(cpu);
	sched_tick_start(cpu);
	return 0;
}

#ifdef CONFIG_HOTPLUG_CPU
int sched_cpu_dying(unsigned int cpu)
{
	struct rq *rq = cpu_rq(cpu);
	unsigned long flags;

	sched_tick_stop(cpu);
	raw_spin_lock_irqsave(&rq->lock, flags);
	set_rq_offline(rq);
	migrate_tasks(rq);
	raw_spin_unlock_irqrestore(&rq->lock, flags);

	hrtick_clear(rq);
	return 0;
}
#endif

#ifdef CONFIG_SMP
static void sched_init_topology_cpumask_early(void)
{
	int cpu, level;
	cpumask_t *tmp;

	for_each_possible_cpu(cpu) {
		for (level = 0; level < NR_CPU_AFFINITY_CHK_LEVEL; level++) {
			tmp = &(per_cpu(sched_cpu_affinity_chk_masks, cpu)[level]);
			cpumask_copy(tmp, cpu_possible_mask);
			cpumask_clear_cpu(cpu, tmp);
		}
		per_cpu(sched_cpu_affinity_chk_end_masks, cpu) =
			&(per_cpu(sched_cpu_affinity_chk_masks, cpu)[1]);
	}
}

static void sched_init_topology_cpumask(void)
{
	int cpu;
	cpumask_t *chk;

	for_each_online_cpu(cpu) {
		cpu_rq(cpu)->balance_inc = BALANCE_INTERVAL +
			BALANCE_INTERVAL / num_online_cpus() * cpu;

		chk = &(per_cpu(sched_cpu_affinity_chk_masks, cpu)[0]);

		cpumask_setall(chk);
		cpumask_clear_cpu(cpu, chk);
#ifdef CONFIG_SCHED_SMT
		if (cpumask_and(chk, chk, topology_sibling_cpumask(cpu))) {
			printk(KERN_INFO "pds: cpu #%d affinity check mask - smt 0x%08lx",
			       cpu, (chk++)->bits[0]);
			per_cpu(cpu_has_smt_sibling, cpu) = 1;
		}
		cpumask_complement(chk, topology_sibling_cpumask(cpu));
#endif
#ifdef CONFIG_SCHED_MC
		if (cpumask_and(chk, chk, cpu_coregroup_mask(cpu)))
			printk(KERN_INFO "pds: cpu #%d affinity check mask - coregroup 0x%08lx",
			       cpu, (chk++)->bits[0]);
		cpumask_complement(chk, cpu_coregroup_mask(cpu));
#endif

		/**
		 * Set up sd_llc_id per CPU
		 */
		per_cpu(sd_llc_id, cpu) =
			cpumask_first(cpu_coregroup_mask(cpu));

		if (cpumask_and(chk, chk, topology_core_cpumask(cpu)))
			printk(KERN_INFO "pds: cpu #%d affinity check mask - core 0x%08lx",
			       cpu, (chk++)->bits[0]);
		cpumask_complement(chk, topology_core_cpumask(cpu));

		if (cpumask_and(chk, chk, cpu_online_mask))
			printk(KERN_INFO "pds: cpu #%d affinity check mask - others 0x%08lx",
			       cpu, (chk++)->bits[0]);

		per_cpu(sched_cpu_affinity_chk_end_masks, cpu) = chk;
	}
}
#endif

void __init sched_init_smp(void)
{
	/* Move init over to a non-isolated CPU */
	if (set_cpus_allowed_ptr(current, housekeeping_cpumask(HK_FLAG_DOMAIN)) < 0)
		BUG();

#ifdef CONFIG_SCHED_SMT
	cpumask_clear(&sched_cpu_sb_suppress_mask);
#endif

	cpumask_copy(&sched_rq_queued_masks[SCHED_RQ_EMPTY], cpu_online_mask);

	sched_init_topology_cpumask();

	sched_smp_initialized = true;
}
#else
void __init sched_init_smp(void)
{
}
#endif /* CONFIG_SMP */

int in_sched_functions(unsigned long addr)
{
	return in_lock_functions(addr) ||
		(addr >= (unsigned long)__sched_text_start
		&& addr < (unsigned long)__sched_text_end);
}

void __init sched_init(void)
{
	int i;
	struct rq *rq;

	print_scheduler_version();

	sched_clock_init();

	wait_bit_init();

#ifdef CONFIG_SMP
	for (i = 0; i < NR_SCHED_RQ_QUEUED_LEVEL; i++)
		cpumask_clear(&sched_rq_queued_masks[i]);
	cpumask_setall(&sched_rq_queued_masks[SCHED_RQ_EMPTY]);
	set_bit(SCHED_RQ_EMPTY, sched_rq_queued_masks_bitmap);

	cpumask_clear(&sched_rq_pending_mask);
#else
	uprq = &per_cpu(runqueues, 0);
#endif
	for_each_possible_cpu(i) {
		rq = cpu_rq(i);
		FULL_INIT_SKIPLIST_NODE(&rq->sl_header);
		raw_spin_lock_init(&rq->lock);
		rq->dither = 0;
		rq->nr_running = rq->nr_uninterruptible = 0;
		rq->calc_load_active = 0;
		rq->calc_load_update = jiffies + LOAD_FREQ;
#ifdef CONFIG_SMP
		rq->online = false;
		rq->cpu = i;
		rq->next_balance = 0UL;

		rq->queued_level = SCHED_RQ_EMPTY;

#ifdef CONFIG_SCHED_SMT
		per_cpu(cpu_has_smt_sibling, i)  = 0;
		rq->active_balance = 0;
#endif
#endif
		rq->nr_switches = 0;
		atomic_set(&rq->nr_iowait, 0);
		rq->iso_ticks = 0;
		rq->iso_refractory = 0;
		hrtick_rq_init(rq);
	}
#ifdef CONFIG_SMP
	/* Set rq->online for cpu 0 */
	cpu_rq(0)->online = true;
#endif

	/*
	 * The boot idle thread does lazy MMU switching as well:
	 */
	mmgrab(&init_mm);
	enter_lazy_tlb(&init_mm, current);

	/*
	 * Make us the idle thread. Technically, schedule() should not be
	 * called from this thread, however somewhere below it might be,
	 * but because we are the idle thread, we just pick up running again
	 * when this runqueue becomes "idle".
	 */
	init_idle(current, smp_processor_id());

	calc_load_update = jiffies + LOAD_FREQ;

#ifdef CONFIG_SMP
	idle_thread_set_boot_cpu();

	sched_init_topology_cpumask_early();

#ifdef CONFIG_SCHED_SMT
	open_softirq(SCHED_SOFTIRQ, pds_run_rebalance);
#endif
#endif /* SMP */

	init_schedstats();
}

#ifdef CONFIG_DEBUG_ATOMIC_SLEEP
static inline int preempt_count_equals(int preempt_offset)
{
	int nested = preempt_count() + rcu_preempt_depth();

	return (nested == preempt_offset);
}

void __might_sleep(const char *file, int line, int preempt_offset)
{
	/*
	 * Blocking primitives will set (and therefore destroy) current->state,
	 * since we will exit with TASK_RUNNING make sure we enter with it,
	 * otherwise we will destroy state.
	 */
	WARN_ONCE(current->state != TASK_RUNNING && current->task_state_change,
			"do not call blocking ops when !TASK_RUNNING; "
			"state=%lx set at [<%p>] %pS\n",
			current->state,
			(void *)current->task_state_change,
			(void *)current->task_state_change);

	___might_sleep(file, line, preempt_offset);
}
EXPORT_SYMBOL(__might_sleep);

void ___might_sleep(const char *file, int line, int preempt_offset)
{
	/* Ratelimiting timestamp: */
	static unsigned long prev_jiffy;

	unsigned long preempt_disable_ip;

	/* WARN_ON_ONCE() by default, no rate limit required: */
	rcu_sleep_check();

	if ((preempt_count_equals(preempt_offset) && !irqs_disabled() &&
	     !is_idle_task(current)) ||
	    system_state == SYSTEM_BOOTING || system_state > SYSTEM_RUNNING ||
	    oops_in_progress)
		return;
	if (time_before(jiffies, prev_jiffy + HZ) && prev_jiffy)
		return;
	prev_jiffy = jiffies;

	/* Save this before calling printk(), since that will clobber it: */
	preempt_disable_ip = get_preempt_disable_ip(current);

	printk(KERN_ERR
		"BUG: sleeping function called from invalid context at %s:%d\n",
			file, line);
	printk(KERN_ERR
		"in_atomic(): %d, irqs_disabled(): %d, pid: %d, name: %s\n",
			in_atomic(), irqs_disabled(),
			current->pid, current->comm);

	if (task_stack_end_corrupted(current))
		printk(KERN_EMERG "Thread overran stack, or stack corrupted\n");

	debug_show_held_locks(current);
	if (irqs_disabled())
		print_irqtrace_events(current);
#ifdef CONFIG_DEBUG_PREEMPT
	if (!preempt_count_equals(preempt_offset)) {
		pr_err("Preemption disabled at:");
		print_ip_sym(preempt_disable_ip);
		pr_cont("\n");
	}
#endif
	dump_stack();
	add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
}
EXPORT_SYMBOL(___might_sleep);
#endif

#ifdef CONFIG_MAGIC_SYSRQ
void normalize_rt_tasks(void)
{
	struct task_struct *g, *p;
	struct sched_attr attr = {
		.sched_policy = SCHED_NORMAL,
	};

	read_lock(&tasklist_lock);
	for_each_process_thread(g, p) {
		/*
		 * Only normalize user tasks:
		 */
		if (p->flags & PF_KTHREAD)
			continue;

		if (!rt_task(p) && !iso_task(p)) {
			/*
			 * Renice negative nice level userspace
			 * tasks back to 0:
			 */
			if (task_nice(p) < 0)
				set_user_nice(p, 0);
			continue;
		}

		__sched_setscheduler(p, &attr, false, false);
	}
	read_unlock(&tasklist_lock);
}
#endif /* CONFIG_MAGIC_SYSRQ */

#if defined(CONFIG_IA64) || defined(CONFIG_KGDB_KDB)
/*
 * These functions are only useful for the IA64 MCA handling, or kdb.
 *
 * They can only be called when the whole system has been
 * stopped - every CPU needs to be quiescent, and no scheduling
 * activity can take place. Using them for anything else would
 * be a serious bug, and as a result, they aren't even visible
 * under any other configuration.
 */

/**
 * curr_task - return the current task for a given CPU.
 * @cpu: the processor in question.
 *
 * ONLY VALID WHEN THE WHOLE SYSTEM IS STOPPED!
 *
 * Return: The current task for @cpu.
 */
struct task_struct *curr_task(int cpu)
{
	return cpu_curr(cpu);
}

#endif /* defined(CONFIG_IA64) || defined(CONFIG_KGDB_KDB) */

#ifdef CONFIG_IA64
/**
 * set_curr_task - set the current task for a given CPU.
 * @cpu: the processor in question.
 * @p: the task pointer to set.
 *
 * Description: This function must only be used when non-maskable interrupts
 * are serviced on a separate stack.  It allows the architecture to switch the
 * notion of the current task on a CPU in a non-blocking manner.  This function
 * must be called with all CPU's synchronised, and interrupts disabled, the
 * and caller must save the original value of the current task (see
 * curr_task() above) and restore that value before reenabling interrupts and
 * re-starting the system.
 *
 * ONLY VALID WHEN THE WHOLE SYSTEM IS STOPPED!
 */
void ia64_set_curr_task(int cpu, struct task_struct *p)
{
	cpu_curr(cpu) = p;
}

#endif

#ifdef CONFIG_SCHED_DEBUG
void proc_sched_show_task(struct task_struct *p, struct pid_namespace *ns,
			  struct seq_file *m)
{}

void proc_sched_set_task(struct task_struct *p)
{}
#endif

#undef CREATE_TRACE_POINTS
