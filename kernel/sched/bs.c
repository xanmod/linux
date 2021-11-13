// SPDX-License-Identifier: GPL-2.0
/*
 * TT Scheduler Class (SCHED_NORMAL/SCHED_BATCH)
 *
 *  Copyright (C) 2021, Hamad Al Marri <hamad.s.almarri@gmail.com>
 */
#include "sched.h"
#include "pelt.h"
#include "tt_stats.h"
#include "fair_numa.h"
#include "bs.h"

unsigned int __read_mostly tt_max_lifetime	= 22000; // in ms

#define INTERACTIVE_HRRN	2U
#define RT_WAIT_DELTA		800000U
#define RT_BURST_DELTA		2000000U
#define RT_BURST_MAX		4000000U

#define HZ_PERIOD (1000000000 / HZ)
#define RACE_TIME 40000000
#define FACTOR (RACE_TIME / HZ_PERIOD)

#define YIELD_MARK(ttn)		((ttn)->vruntime |= 0x8000000000000000ULL)
#define YIELD_UNMARK(ttn)	((ttn)->vruntime &= 0x7FFFFFFFFFFFFFFFULL)

#define IS_REALTIME(ttn)	((ttn)->task_type == TT_REALTIME)
#define IS_INTERACTIVE(ttn)	((ttn)->task_type == TT_INTERACTIVE)
#define IS_NO_TYPE(ttn)		((ttn)->task_type == TT_NO_TYPE)
#define IS_CPU_BOUND(ttn)	((ttn)->task_type == TT_CPU_BOUND)
#define IS_BATCH(ttn)		((ttn)->task_type == TT_BATCH)

#define GEQ(a, b) ((s64)((a) - (b)) >= 0)	// is a >= b
#define LEQ(a, b) ((s64)((a) - (b)) <= 0)	// is a <= b
#define LES(a, b) ((s64)((a) - (b)) < 0)	// is a <  b
#define EQ_D(a, b, d) (LEQ(a, b + d) && GEQ(a, b - d))

#define HRRN_PERCENT(ttn, now) (((ttn)->vruntime * 1000ULL) / ((now) - (ttn)->start_time))

static inline bool is_interactive(struct tt_node *ttn, u64 now, u64 _hrrn)
{
	u64 wait;

	if (LES(_hrrn, (u64) INTERACTIVE_HRRN))
		return false;

	wait = now - se_of(ttn)->exec_start;
	if (wait && EQ_D(wait, ttn->prev_wait_time, RT_WAIT_DELTA))
		return false;

	return true;
}

static inline bool is_realtime(struct tt_node *ttn, u64 now, int flags)
{
	u64 life_time, wait;

	// it has slept at least once
	if (!ttn->wait_time)
		return false;

	// life time >= 0.5s
	life_time = now - task_of(se_of(ttn))->start_time;
	if (LES(life_time, 500000000ULL))
		return false;

	// don't check wait time for migrated tasks
	if (!(flags & ENQUEUE_MIGRATED)) {
		/* it has relatively equal sleeping/waiting times
		 * (ex. it sleeps for ~10ms and run repeatedly)
		 */
		wait = now - se_of(ttn)->exec_start;
		if (wait && !EQ_D(wait, ttn->prev_wait_time, RT_WAIT_DELTA))
			return false;
	}

	// bursts before sleep are relatively equal (delta 2ms)
	if (!EQ_D(ttn->burst, ttn->prev_burst, RT_BURST_DELTA))
		return false;

	// burst before sleep is <= 4ms
	if (LEQ(ttn->burst, RT_BURST_MAX) &&
	    LEQ(ttn->curr_burst, RT_BURST_MAX))
		return true;

	return false;
}

static inline bool is_cpu_bound(struct tt_node *ttn)
{
	u64 _hrrn_percent;

	_hrrn_percent = ttn->vruntime * 100ULL;
	_hrrn_percent /= ttn->wait_time + ttn->vruntime;

	// HRRN >= 80%
	return (GEQ(_hrrn_percent, 80ULL));
}

static inline bool is_batch(struct tt_node *ttn, u64 _hrrn)
{
	// HRRN > 50%
	return (LES(_hrrn, 2ULL));
}

static void detect_type(struct tt_node *ttn, u64 now, int flags)
{
	unsigned int new_type = TT_NO_TYPE;
	u64 _hrrn;

	if (ttn->vruntime == 1) {
		ttn->task_type = TT_NO_TYPE;
		return;
	}

	_hrrn = (ttn->wait_time + ttn->vruntime) / ttn->vruntime;

	if (is_realtime(ttn, now, flags))
		new_type = TT_REALTIME;
	else if (is_interactive(ttn, now, _hrrn))
		new_type = TT_INTERACTIVE;
	else if (is_cpu_bound(ttn))
		new_type = TT_CPU_BOUND;
	else if (is_batch(ttn, _hrrn))
		new_type = TT_BATCH;

	if (new_type == TT_REALTIME) {
		ttn->rt_sticky = 4;
	} else if (IS_REALTIME(ttn) && ttn->rt_sticky) {
		ttn->rt_sticky--;
		return;
	}

	ttn->task_type = new_type;
}

static void normalize_lifetime(u64 now, struct tt_node *ttn)
{
	u64 max_life_ns, life_time, old_hrrn_x;
	s64 diff;

	/*
	 * left shift 20 bits is approximately = * 1000000
	 * we don't need the precision of life time
	 * Ex. for 22s, with left shift (20bits) == 23.06s
	 */
	max_life_ns	= ((u64) tt_max_lifetime) << 20;
	life_time	= now - ttn->start_time;
	diff		= life_time - max_life_ns;

	if (likely(diff < 0))
		return;

	// unmark YIELD. No need to check or remark since
	// this normalize action doesn't happen very often
	YIELD_UNMARK(ttn);

	// multiply life_time by 1024 for more precision
	old_hrrn_x = (life_time << 7) / ((ttn->vruntime >> 3) | 1);

	// reset life to half max_life (i.e ~15s)
	ttn->start_time = now - (max_life_ns >> 1);

	// avoid division by zero
	if (old_hrrn_x == 0) old_hrrn_x = 1;

	// reset vruntime based on old hrrn ratio
	ttn->vruntime = ((max_life_ns << 9) / old_hrrn_x) | 1;
}

static u64 convert_to_vruntime(u64 delta, struct sched_entity *se)
{
	struct task_struct *p = task_of(se);
	s64 prio_diff;
	int prio = IS_REALTIME(&se->tt_node) ? -20 : PRIO_TO_NICE(p->prio);

	if (prio == 0)
		return delta;

	prio_diff = prio * 1000000;
	prio_diff /= FACTOR;

	if ((s64)(delta + prio_diff) < 0)
		return 1;

	return delta + prio_diff;
}

static void update_curr(struct cfs_rq *cfs_rq)
{
	struct sched_entity *curr = cfs_rq->curr;
	struct tt_node *ttn = &curr->tt_node;
	u64 now = sched_clock();
	u64 delta_exec;

	if (unlikely(!curr))
		return;

	delta_exec = now - curr->exec_start;
	if (unlikely((s64)delta_exec <= 0))
		return;

	curr->exec_start = now;
	curr->sum_exec_runtime += delta_exec;

	ttn->curr_burst += delta_exec;
	ttn->vruntime += convert_to_vruntime(delta_exec, curr);
	detect_type(ttn, now, 0);

	normalize_lifetime(now, &curr->tt_node);
}

static void update_curr_fair(struct rq *rq)
{
	update_curr(cfs_rq_of(&rq->curr->se));
}

/**
 * Should `a` preempts `b`?
 */
static inline bool
entity_before(struct tt_node *a, struct tt_node *b)
{
	u64 now = sched_clock();

	return (int)(HRRN_PERCENT(a, now) - HRRN_PERCENT(b, now)) < 0;
}

static void __enqueue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	struct tt_node *ttn = &se->tt_node;

	ttn->next = ttn->prev = NULL;

	// if empty
	if (!cfs_rq->head) {
		cfs_rq->head	= ttn;
	}
	else {
		ttn->next	     = cfs_rq->head;
		cfs_rq->head->prev   = ttn;
		cfs_rq->head         = ttn;
	}
}

static void __dequeue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	struct tt_node *ttn = &se->tt_node;
	struct tt_node *prev, *next;

	// if only one se in rq
	if (cfs_rq->head->next == NULL) {
		cfs_rq->head = NULL;
	}
	// if it is the head
	else if (ttn == cfs_rq->head) {
		cfs_rq->head	   = cfs_rq->head->next;
		cfs_rq->head->prev = NULL;
	}
	// if in the middle
	else {
		prev = ttn->prev;
		next = ttn->next;

		prev->next = next;
		if (next)
			next->prev = prev;
	}
}

static void
enqueue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se, int flags)
{
	struct tt_node *ttn = &se->tt_node;
	bool curr = cfs_rq->curr == se;
	bool wakeup = (flags & ENQUEUE_WAKEUP);
	u64 now = sched_clock();
	u64 wait;

	if (wakeup) {
		wait = now - se->exec_start;
		ttn->wait_time += wait;
		detect_type(ttn, now, flags);

		ttn->prev_wait_time = wait;
	} else {
		detect_type(ttn, now, flags);
	}

	update_curr(cfs_rq);

	/*
	 * When enqueuing a sched_entity, we must:
	 *   - Update loads to have both entity and cfs_rq synced with now.
	 *   - Add its load to cfs_rq->runnable_avg
	 *   - For group_entity, update its weight to reflect the new share of
	 *     its group cfs_rq
	 *   - Add its new weight to cfs_rq->load.weight
	 */
	update_load_avg(cfs_rq, se, UPDATE_TG | DO_ATTACH);
	account_entity_enqueue(cfs_rq, se);
	check_schedstat_required();
	update_stats_enqueue(cfs_rq, se, flags);

	if (!curr)
		__enqueue_entity(cfs_rq, se);

	se->on_rq = 1;
}

static void
dequeue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se, int flags)
{
	struct tt_node *ttn = &se->tt_node;
	bool sleep = (flags & DEQUEUE_SLEEP);

	if (sleep) {
		ttn->prev_burst = ttn->burst;
		ttn->burst = ttn->curr_burst;
		ttn->curr_burst = 0;

		if (IS_CPU_BOUND(ttn))
			ttn->task_type = TT_BATCH;
	}

	update_curr(cfs_rq);

	/*
	 * When dequeuing a sched_entity, we must:
	 *   - Update loads to have both entity and cfs_rq synced with now.
	 *   - Subtract its load from the cfs_rq->runnable_avg.
	 *   - Subtract its previous weight from cfs_rq->load.weight.
	 *   - For group entity, update its weight to reflect the new share
	 *     of its group cfs_rq.
	 */
	update_load_avg(cfs_rq, se, UPDATE_TG);
	update_stats_dequeue(cfs_rq, se, flags);

	if (se != cfs_rq->curr)
		__dequeue_entity(cfs_rq, se);

	se->on_rq = 0;
	account_entity_dequeue(cfs_rq, se);
}

static void
enqueue_task_fair(struct rq *rq, struct task_struct *p, int flags)
{
	struct sched_entity *se = &p->se;
	struct cfs_rq *cfs_rq = cfs_rq_of(se);
	int idle_h_nr_running = task_has_idle_policy(p);
	int task_new = !(flags & ENQUEUE_WAKEUP);

	/*
	 * The code below (indirectly) updates schedutil which looks at
	 * the cfs_rq utilization to select a frequency.
	 * Let's add the task's estimated utilization to the cfs_rq's
	 * estimated utilization, before we update schedutil.
	 */
	util_est_enqueue(&rq->cfs, p);

	/*
	 * If in_iowait is set, the code below may not trigger any cpufreq
	 * utilization updates, so do it here explicitly with the IOWAIT flag
	 * passed.
	 */
	if (p->in_iowait)
		cpufreq_update_util(rq, SCHED_CPUFREQ_IOWAIT);

	if (!se->on_rq) {
		enqueue_entity(cfs_rq, se, flags);
		cfs_rq->h_nr_running++;
		cfs_rq->idle_h_nr_running += idle_h_nr_running;
	}

	add_nr_running(rq, 1);

	if (!task_new)
		update_overutilized_status(rq);
}

static void dequeue_task_fair(struct rq *rq, struct task_struct *p, int flags)
{
	struct sched_entity *se = &p->se;
	struct cfs_rq *cfs_rq = cfs_rq_of(se);
	int idle_h_nr_running = task_has_idle_policy(p);
	int task_sleep = flags & DEQUEUE_SLEEP;

	util_est_dequeue(&rq->cfs, p);

	dequeue_entity(cfs_rq, se, flags);

	cfs_rq->h_nr_running--;
	cfs_rq->idle_h_nr_running -= idle_h_nr_running;

	sub_nr_running(rq, 1);
	util_est_update(&rq->cfs, p, task_sleep);
}

static void yield_task_fair(struct rq *rq)
{
	struct task_struct *curr = rq->curr;
	struct cfs_rq *cfs_rq = task_cfs_rq(curr);

	YIELD_MARK(&curr->se.tt_node);

	/*
	 * Are we the only task in the tree?
	 */
	if (unlikely(rq->nr_running == 1))
		return;

	if (curr->policy != SCHED_BATCH) {
		update_rq_clock(rq);
		/*
		 * Update run-time statistics of the 'current'.
		 */
		update_curr(cfs_rq);
		/*
		 * Tell update_rq_clock() that we've just updated,
		 * so we don't do microscopic update in schedule()
		 * and double the fastpath cost.
		 */
		rq_clock_skip_update(rq);
	}
}

static bool yield_to_task_fair(struct rq *rq, struct task_struct *p)
{
	yield_task_fair(rq);
	return true;
}

static void
set_next_entity(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	if (se->on_rq)
		__dequeue_entity(cfs_rq, se);

	se->exec_start = sched_clock();
	cfs_rq->curr = se;
	se->prev_sum_exec_runtime = se->sum_exec_runtime;
}

static struct sched_entity *
pick_next_entity(struct cfs_rq *cfs_rq, struct sched_entity *curr)
{
	struct tt_node *ttn = cfs_rq->head;
	struct tt_node *next;

	if (!ttn)
		return curr;

	next = ttn->next;
	while (next) {
		if (entity_before(next, ttn))
			ttn = next;

		next = next->next;
	}

	if (curr && entity_before(&curr->tt_node, ttn))
		return curr;

	return se_of(ttn);
}

struct task_struct *
pick_next_task_fair(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
{
	struct cfs_rq *cfs_rq = &rq->cfs;
	struct sched_entity *se;
	struct task_struct *p;
	int new_tasks;

again:
	if (!sched_fair_runnable(rq))
		goto idle;

	if (prev)
		put_prev_task(rq, prev);

	se = pick_next_entity(cfs_rq, NULL);
	set_next_entity(cfs_rq, se);

	p = task_of(se);

	if (prev)
		YIELD_UNMARK(&prev->se.tt_node);

done: __maybe_unused;
#ifdef CONFIG_SMP
	/*
	 * Move the next running task to the front of
	 * the list, so our cfs_tasks list becomes MRU
	 * one.
	 */
	list_move(&p->se.group_node, &rq->cfs_tasks);
#endif

	return p;

idle:
	if (!rf)
		return NULL;

	new_tasks = newidle_balance(rq, rf);

	/*
	 * Because newidle_balance() releases (and re-acquires) rq->lock, it is
	 * possible for any higher priority task to appear. In that case we
	 * must re-start the pick_next_entity() loop.
	 */
	if (new_tasks < 0)
		return RETRY_TASK;

	if (new_tasks > 0)
		goto again;

	/*
	 * rq is about to be idle, check if we need to update the
	 * lost_idle_time of clock_pelt
	 */
	update_idle_rq_clock_pelt(rq);

	return NULL;
}

static struct task_struct *__pick_next_task_fair(struct rq *rq)
{
	return pick_next_task_fair(rq, NULL, NULL);
}

#ifdef CONFIG_SMP
static struct task_struct *pick_task_fair(struct rq *rq)
{
	struct sched_entity *se;
	struct cfs_rq *cfs_rq = &rq->cfs;
	struct sched_entity *curr = cfs_rq->curr;

	if (!cfs_rq->nr_running)
		return NULL;

	/* When we pick for a remote RQ, we'll not have done put_prev_entity() */
	if (curr) {
		if (curr->on_rq)
			update_curr(cfs_rq);
		else
			curr = NULL;
	}

	se = pick_next_entity(cfs_rq, curr);

	return task_of(se);
}
#endif

static void put_prev_entity(struct cfs_rq *cfs_rq, struct sched_entity *prev)
{
	/*
	 * If still on the runqueue then deactivate_task()
	 * was not called and update_curr() has to be done:
	 */
	if (prev->on_rq)
		update_curr(cfs_rq);

	if (prev->on_rq)
		__enqueue_entity(cfs_rq, prev);

	cfs_rq->curr = NULL;
}

static void put_prev_task_fair(struct rq *rq, struct task_struct *prev)
{
	struct sched_entity *se = &prev->se;

	put_prev_entity(cfs_rq_of(se), se);
}

static void set_next_task_fair(struct rq *rq, struct task_struct *p, bool first)
{
	struct sched_entity *se = &p->se;
	struct cfs_rq *cfs_rq = cfs_rq_of(se);

#ifdef CONFIG_SMP
	if (task_on_rq_queued(p)) {
		/*
		 * Move the next running task to the front of the list, so our
		 * cfs_tasks list becomes MRU one.
		 */
		list_move(&se->group_node, &rq->cfs_tasks);
	}
#endif

	set_next_entity(cfs_rq, se);
}

static void
check_preempt_tick(struct cfs_rq *cfs_rq, struct sched_entity *curr)
{
	if (pick_next_entity(cfs_rq, curr) != curr)
		resched_curr(rq_of(cfs_rq));
}

static void
entity_tick(struct cfs_rq *cfs_rq, struct sched_entity *curr, int queued)
{
	update_curr(cfs_rq);

	if (cfs_rq->nr_running > 1)
		check_preempt_tick(cfs_rq, curr);
}

static void check_preempt_wakeup(struct rq *rq, struct task_struct *p, int wake_flags)
{
	struct task_struct *curr = rq->curr;
	struct sched_entity *se = &curr->se, *wse = &p->se;

	if (unlikely(se == wse))
		return;

	if (test_tsk_need_resched(curr))
		return;

	/* Idle tasks are by definition preempted by non-idle tasks. */
	if (unlikely(task_has_idle_policy(curr)) &&
	    likely(!task_has_idle_policy(p)))
		goto preempt;

	/*
	 * Batch and idle tasks do not preempt non-idle tasks (their preemption
	 * is driven by the tick):
	 */
	if (unlikely(p->policy != SCHED_NORMAL) || !sched_feat(WAKEUP_PREEMPTION))
		return;

	update_curr(cfs_rq_of(se));

	if (entity_before(&wse->tt_node, &se->tt_node))
		goto preempt;

	return;

preempt:
	resched_curr(rq);
}

#ifdef CONFIG_SMP
static int
balance_fair(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
{
	if (rq->nr_running)
		return 1;

	return newidle_balance(rq, rf) != 0;
}

static void record_wakee(struct task_struct *p)
{
	/*
	 * Only decay a single time; tasks that have less then 1 wakeup per
	 * jiffy will not have built up many flips.
	 */
	if (time_after(jiffies, current->wakee_flip_decay_ts + HZ)) {
		current->wakee_flips >>= 1;
		current->wakee_flip_decay_ts = jiffies;
	}

	if (current->last_wakee != p) {
		current->last_wakee = p;
		current->wakee_flips++;
	}
}

/*
 * Detect M:N waker/wakee relationships via a switching-frequency heuristic.
 *
 * A waker of many should wake a different task than the one last awakened
 * at a frequency roughly N times higher than one of its wakees.
 *
 * In order to determine whether we should let the load spread vs consolidating
 * to shared cache, we look for a minimum 'flip' frequency of llc_size in one
 * partner, and a factor of lls_size higher frequency in the other.
 *
 * With both conditions met, we can be relatively sure that the relationship is
 * non-monogamous, with partner count exceeding socket size.
 *
 * Waker/wakee being client/server, worker/dispatcher, interrupt source or
 * whatever is irrelevant, spread criteria is apparent partner count exceeds
 * socket size.
 */
static int wake_wide(struct task_struct *p)
{
	unsigned int master = current->wakee_flips;
	unsigned int slave = p->wakee_flips;
	int factor = __this_cpu_read(sd_llc_size);

	if (master < slave)
		swap(master, slave);
	if (slave < factor || master < slave * factor)
		return 0;
	return 1;
}

/*
 * The purpose of wake_affine() is to quickly determine on which CPU we can run
 * soonest. For the purpose of speed we only consider the waking and previous
 * CPU.
 *
 * wake_affine_idle() - only considers 'now', it check if the waking CPU is
 *			cache-affine and is (or	will be) idle.
 */
static int
wake_affine_idle(int this_cpu, int prev_cpu, int sync)
{
	/*
	 * If this_cpu is idle, it implies the wakeup is from interrupt
	 * context. Only allow the move if cache is shared. Otherwise an
	 * interrupt intensive workload could force all tasks onto one
	 * node depending on the IO topology or IRQ affinity settings.
	 *
	 * If the prev_cpu is idle and cache affine then avoid a migration.
	 * There is no guarantee that the cache hot data from an interrupt
	 * is more important than cache hot data on the prev_cpu and from
	 * a cpufreq perspective, it's better to have higher utilisation
	 * on one CPU.
	 */
	if (available_idle_cpu(this_cpu) && cpus_share_cache(this_cpu, prev_cpu))
		return available_idle_cpu(prev_cpu) ? prev_cpu : this_cpu;

	if (sync && cpu_rq(this_cpu)->nr_running == 1)
		return this_cpu;

	if (available_idle_cpu(prev_cpu))
		return prev_cpu;

	return nr_cpumask_bits;
}

static int
wake_affine(struct task_struct *p, int this_cpu, int prev_cpu, int sync)
{
	int target = nr_cpumask_bits;

	target = wake_affine_idle(this_cpu, prev_cpu, sync);

	if (target == nr_cpumask_bits)
		return prev_cpu;

	return target;
}

static int
select_task_rq_fair(struct task_struct *p, int prev_cpu, int wake_flags)
{
	struct rq *rq = cpu_rq(prev_cpu);
	unsigned int min_prev = rq->nr_running;
	unsigned int min = rq->nr_running;
	int cpu = smp_processor_id();
	int this_cpu = smp_processor_id();
	int new_cpu = prev_cpu;
	int sync = (wake_flags & WF_SYNC) && !(current->flags & PF_EXITING);
	int want_affine = 0;

	/*
	 * required for stable ->cpus_allowed
	 */
	lockdep_assert_held(&p->pi_lock);
	if (wake_flags & WF_TTWU) {
		record_wakee(p);
		want_affine = !wake_wide(p) && cpumask_test_cpu(cpu, p->cpus_ptr);
	}

	for_each_cpu_wrap(cpu, cpu_online_mask, this_cpu) {
		if (unlikely(!cpumask_test_cpu(cpu, p->cpus_ptr)))
			continue;

		if (want_affine) {
			if (cpu != prev_cpu)
				new_cpu = wake_affine(p, cpu, prev_cpu, sync);

			return new_cpu;
		}

		if (cpu_rq(cpu)->nr_running < min) {
			new_cpu = cpu;
			min = cpu_rq(cpu)->nr_running;
		}
	}

	if (min == min_prev)
		return prev_cpu;

	return new_cpu;
}

static int
can_migrate_task(struct task_struct *p, int dst_cpu, struct rq *src_rq)
{
	if (task_running(src_rq, p))
		return 0;

	/* Disregard pcpu kthreads; they are where they need to be. */
	if (kthread_is_per_cpu(p))
		return 0;

	if (!cpumask_test_cpu(dst_cpu, p->cpus_ptr))
		return 0;

	return 1;
}

static void pull_from(struct rq *dist_rq,
		      struct rq *src_rq,
		      struct rq_flags *src_rf,
		      struct task_struct *p)
{
	struct rq_flags rf;

	// detach task
	deactivate_task(src_rq, p, DEQUEUE_NOCLOCK);
	set_task_cpu(p, cpu_of(dist_rq));

	// unlock src rq
	rq_unlock(src_rq, src_rf);

	// lock dist rq
	rq_lock(dist_rq, &rf);
	update_rq_clock(dist_rq);

	activate_task(dist_rq, p, ENQUEUE_NOCLOCK);
	check_preempt_curr(dist_rq, p, 0);

	// unlock dist rq
	rq_unlock(dist_rq, &rf);

	local_irq_restore(src_rf->flags);
}

static int move_task(struct rq *dist_rq, struct rq *src_rq,
			struct rq_flags *src_rf)
{
	struct cfs_rq *src_cfs_rq = &src_rq->cfs;
	struct task_struct *p;
	struct tt_node *ttn = src_cfs_rq->head;

	while (ttn) {
		p = task_of(se_of(ttn));
		if (can_migrate_task(p, cpu_of(dist_rq), src_rq)) {
			pull_from(dist_rq, src_rq, src_rf, p);
			return 1;
		}

		ttn = ttn->next;
	}

	/*
	 * Here we know we have not migrated any task,
	 * thus, we need to unlock and return 0
	 * Note: the pull_from does the unlocking for us.
	 */
	rq_unlock(src_rq, src_rf);
	local_irq_restore(src_rf->flags);

	return 0;
}

static inline int on_null_domain(struct rq *rq)
{
	return unlikely(!rcu_dereference_sched(rq->sd));
}

#include "bs_nohz.h"

static int newidle_balance(struct rq *this_rq, struct rq_flags *rf)
{
	int this_cpu = this_rq->cpu;
	struct rq *src_rq;
	int src_cpu = -1, cpu;
	int pulled_task = 0;
	unsigned int max = 0;
	struct rq_flags src_rf;

	/*
	 * We must set idle_stamp _before_ calling idle_balance(), such that we
	 * measure the duration of idle_balance() as idle time.
	 */
	this_rq->idle_stamp = rq_clock(this_rq);

	/*
	 * Do not pull tasks towards !active CPUs...
	 */
	if (!cpu_active(this_cpu))
		return 0;

	rq_unpin_lock(this_rq, rf);
	raw_spin_unlock(&this_rq->__lock);

	update_blocked_averages(this_cpu);

	for_each_online_cpu(cpu) {
		/*
		 * Stop searching for tasks to pull if there are
		 * now runnable tasks on this rq.
		 */
		if (this_rq->nr_running > 0)
			goto out;

		if (cpu == this_cpu)
			continue;

		src_rq = cpu_rq(cpu);

		if (src_rq->nr_running < 2)
			continue;

		if (src_rq->nr_running > max) {
			max = src_rq->nr_running;
			src_cpu = cpu;
		}
	}

	if (src_cpu != -1) {
		src_rq = cpu_rq(src_cpu);

		rq_lock_irqsave(src_rq, &src_rf);
		update_rq_clock(src_rq);

		if (src_rq->nr_running < 2) {
			rq_unlock(src_rq, &src_rf);
			local_irq_restore(src_rf.flags);
		} else {
			pulled_task = move_task(this_rq, src_rq, &src_rf);
		}
	}

out:
	raw_spin_lock(&this_rq->__lock);

	/*
	 * While browsing the domains, we released the rq lock, a task could
	 * have been enqueued in the meantime. Since we're not going idle,
	 * pretend we pulled a task.
	 */
	if (this_rq->cfs.h_nr_running && !pulled_task)
		pulled_task = 1;

	/* Is there a task of a high priority class? */
	if (this_rq->nr_running != this_rq->cfs.h_nr_running)
		pulled_task = -1;

	if (pulled_task)
		this_rq->idle_stamp = 0;
	else
		nohz_newidle_balance(this_rq);

	rq_repin_lock(this_rq, rf);

	return pulled_task;
}

void trigger_load_balance(struct rq *this_rq)
{
	int this_cpu = cpu_of(this_rq);
	int cpu;
	unsigned int max, min;
	struct rq *max_rq, *min_rq, *c_rq;
	struct rq_flags src_rf;

	if (this_cpu != 0)
		goto out;

	max = min = this_rq->nr_running;
	max_rq = min_rq = this_rq;

	for_each_online_cpu(cpu) {
		c_rq = cpu_rq(cpu);

		/*
		 * Don't need to rebalance while attached to NULL domain or
		 * runqueue CPU is not active
		 */
		if (unlikely(on_null_domain(c_rq) || !cpu_active(cpu)))
			continue;

		if (c_rq->nr_running < min) {
			min = c_rq->nr_running;
			min_rq = c_rq;
		}

		if (c_rq->nr_running > max) {
			max = c_rq->nr_running;
			max_rq = c_rq;
		}
	}

	if (min_rq == max_rq || max - min < 2)
		goto out;

	rq_lock_irqsave(max_rq, &src_rf);
	update_rq_clock(max_rq);

	if (max_rq->nr_running < 2) {
		rq_unlock(max_rq, &src_rf);
		local_irq_restore(src_rf.flags);
		goto out;
	}

	move_task(min_rq, max_rq, &src_rf);

out:
	if (unlikely(on_null_domain(this_rq) || !cpu_active(cpu_of(this_rq))))
		return;

	update_blocked_averages(this_rq->cpu);
	nohz_balancer_kick(this_rq);
}

void update_group_capacity(struct sched_domain *sd, int cpu) {}
#endif /* CONFIG_SMP */

static void task_tick_fair(struct rq *rq, struct task_struct *curr, int queued)
{
	struct sched_entity *se = &curr->se;
	struct cfs_rq *cfs_rq = cfs_rq_of(se);

	entity_tick(cfs_rq, se, queued);

	if (static_branch_unlikely(&sched_numa_balancing))
		task_tick_numa(rq, curr);
}

static void task_fork_fair(struct task_struct *p)
{
	struct cfs_rq *cfs_rq;
	struct sched_entity *curr;
	struct rq *rq = this_rq();
	struct rq_flags rf;
	struct tt_node *ttn = &p->se.tt_node;

	ttn->task_type		= TT_NO_TYPE;
	ttn->vruntime		= 1;
	ttn->prev_wait_time	= 0;
	ttn->wait_time		= 0;
	ttn->prev_burst		= 0;
	ttn->burst		= 0;
	ttn->curr_burst		= 0;
	ttn->rt_sticky		= 0;

	rq_lock(rq, &rf);
	update_rq_clock(rq);

	cfs_rq = task_cfs_rq(current);

	curr = cfs_rq->curr;
	if (curr) {
		update_curr(cfs_rq);

		if (sysctl_sched_child_runs_first)
			resched_curr(rq);
	}

	rq_unlock(rq, &rf);
}

/*
 * All the scheduling class methods:
 */
DEFINE_SCHED_CLASS(fair) = {

	.enqueue_task		= enqueue_task_fair,
	.dequeue_task		= dequeue_task_fair,
	.yield_task		= yield_task_fair,
	.yield_to_task		= yield_to_task_fair,

	.check_preempt_curr	= check_preempt_wakeup,

	.pick_next_task		= __pick_next_task_fair,
	.put_prev_task		= put_prev_task_fair,
	.set_next_task          = set_next_task_fair,

#ifdef CONFIG_SMP
	.balance		= balance_fair,
	.pick_task		= pick_task_fair,
	.select_task_rq		= select_task_rq_fair,
	.migrate_task_rq	= migrate_task_rq_fair,

	.rq_online		= rq_online_fair,
	.rq_offline		= rq_offline_fair,

	.task_dead		= task_dead_fair,
	.set_cpus_allowed	= set_cpus_allowed_common,
#endif

	.task_tick		= task_tick_fair,
	.task_fork		= task_fork_fair,

	.prio_changed		= prio_changed_fair,
	.switched_from		= switched_from_fair,
	.switched_to		= switched_to_fair,

	.get_rr_interval	= get_rr_interval_fair,

	.update_curr		= update_curr_fair,

#ifdef CONFIG_UCLAMP_TASK
	.uclamp_enabled		= 1,
#endif
};

__init void init_sched_fair_class(void)
{
#ifdef CONFIG_SMP
	open_softirq(SCHED_SOFTIRQ, run_rebalance_domains);

#ifdef CONFIG_NO_HZ_COMMON
	nohz.next_balance = jiffies;
	nohz.next_blocked = jiffies;
	zalloc_cpumask_var(&nohz.idle_cpus_mask, GFP_NOWAIT);
#endif
#endif /* SMP */

}
