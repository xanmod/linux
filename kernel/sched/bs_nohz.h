
#ifdef CONFIG_NO_HZ_COMMON

static struct {
	cpumask_var_t idle_cpus_mask;
	atomic_t nr_cpus;
	int has_blocked;		/* Idle CPUS has blocked load */
	unsigned long next_balance;     /* in jiffy units */
	unsigned long next_blocked;	/* Next update of blocked load in jiffies */
} nohz ____cacheline_aligned;

#endif /* CONFIG_NO_HZ_COMMON */

#ifdef CONFIG_NO_HZ_COMMON
static inline bool cfs_rq_has_blocked(struct cfs_rq *cfs_rq)
{
	if (cfs_rq->avg.load_avg)
		return true;

	if (cfs_rq->avg.util_avg)
		return true;

	return false;
}

static inline bool others_have_blocked(struct rq *rq)
{
	if (READ_ONCE(rq->avg_rt.util_avg))
		return true;

	if (READ_ONCE(rq->avg_dl.util_avg))
		return true;

	if (thermal_load_avg(rq))
		return true;

#ifdef CONFIG_HAVE_SCHED_AVG_IRQ
	if (READ_ONCE(rq->avg_irq.util_avg))
		return true;
#endif

	return false;
}

static inline void update_blocked_load_tick(struct rq *rq)
{
	WRITE_ONCE(rq->last_blocked_load_update_tick, jiffies);
}

static inline void update_blocked_load_status(struct rq *rq, bool has_blocked)
{
	if (!has_blocked)
		rq->has_blocked_load = 0;
}
#else
static inline bool cfs_rq_has_blocked(struct cfs_rq *cfs_rq) { return false; }
static inline bool others_have_blocked(struct rq *rq) { return false; }
static inline void update_blocked_load_tick(struct rq *rq) {}
static inline void update_blocked_load_status(struct rq *rq, bool has_blocked) {}
#endif

#ifdef CONFIG_TT_ACCOUNTING_STATS
static bool __update_blocked_others(struct rq *rq, bool *done)
{
	const struct sched_class *curr_class;
	u64 now = rq_clock_pelt(rq);
	unsigned long thermal_pressure;
	bool decayed;

	/*
	 * update_load_avg() can call cpufreq_update_util(). Make sure that RT,
	 * DL and IRQ signals have been updated before updating CFS.
	 */
	curr_class = rq->curr->sched_class;

	thermal_pressure = arch_scale_thermal_pressure(cpu_of(rq));

	decayed = update_rt_rq_load_avg(now, rq, curr_class == &rt_sched_class) |
		  update_dl_rq_load_avg(now, rq, curr_class == &dl_sched_class) |
		  update_thermal_load_avg(rq_clock_thermal(rq), rq, thermal_pressure) |
		  update_irq_load_avg(rq, 0);

	if (others_have_blocked(rq))
		*done = false;

	return decayed;
}

static bool __update_blocked_fair(struct rq *rq, bool *done)
{
	struct cfs_rq *cfs_rq = &rq->cfs;
	bool decayed;

	decayed = update_cfs_rq_load_avg(cfs_rq_clock_pelt(cfs_rq), cfs_rq);
	if (cfs_rq_has_blocked(cfs_rq))
		*done = false;

	return decayed;
}

static void update_blocked_averages(int cpu)
{
	bool decayed = false, done = true;
	struct rq *rq = cpu_rq(cpu);
	struct rq_flags rf;

	rq_lock_irqsave(rq, &rf);
	update_blocked_load_tick(rq);
	update_rq_clock(rq);

	decayed |= __update_blocked_others(rq, &done);
	decayed |= __update_blocked_fair(rq, &done);

	update_blocked_load_status(rq, !done);
	if (decayed)
		cpufreq_update_util(rq, 0);
	rq_unlock_irqrestore(rq, &rf);
}
#else
static void update_blocked_averages(int cpu) {}
#endif

#ifdef CONFIG_NO_HZ_COMMON
/*
 * idle load balancing details
 * - When one of the busy CPUs notice that there may be an idle rebalancing
 *   needed, they will kick the idle load balancer, which then does idle
 *   load balancing for all the idle CPUs.
 * - HK_FLAG_MISC CPUs are used for this task, because HK_FLAG_SCHED not set
 *   anywhere yet.
 */

static inline int find_new_ilb(void)
{
	int ilb;
	const struct cpumask *hk_mask;

	hk_mask = housekeeping_cpumask(HK_FLAG_MISC);

	for_each_cpu_and(ilb, nohz.idle_cpus_mask, hk_mask) {

		if (ilb == smp_processor_id())
			continue;

		if (idle_cpu(ilb))
			return ilb;
	}

	return nr_cpu_ids;
}

/*
 * Kick a CPU to do the nohz balancing, if it is time for it. We pick any
 * idle CPU in the HK_FLAG_MISC housekeeping set (if there is one).
 */
static void kick_ilb(unsigned int flags)
{
	int ilb_cpu;

	/*
	 * Increase nohz.next_balance only when if full ilb is triggered but
	 * not if we only update stats.
	 */
	if (flags & NOHZ_BALANCE_KICK)
		nohz.next_balance = jiffies+1;

	ilb_cpu = find_new_ilb();

	if (ilb_cpu >= nr_cpu_ids)
		return;

	/*
	 * Access to rq::nohz_csd is serialized by NOHZ_KICK_MASK; he who sets
	 * the first flag owns it; cleared by nohz_csd_func().
	 */
	flags = atomic_fetch_or(flags, nohz_flags(ilb_cpu));
	if (flags & NOHZ_KICK_MASK)
		return;

	/*
	 * This way we generate an IPI on the target CPU which
	 * is idle. And the softirq performing nohz idle load balance
	 * will be run before returning from the IPI.
	 */
	smp_call_function_single_async(ilb_cpu, &cpu_rq(ilb_cpu)->nohz_csd);
}

/*
 * Check whether the capacity of the rq has been noticeably reduced by side
 * activity. The imbalance_pct is used for the threshold.
 * Return true is the capacity is reduced
 */
static inline int
check_cpu_capacity(struct rq *rq, struct sched_domain *sd)
{
	return ((rq->cpu_capacity * sd->imbalance_pct) <
				(rq->cpu_capacity_orig * 100));
}

/*
 * Check whether a rq has a misfit task and if it looks like we can actually
 * help that task: we can migrate the task to a CPU of higher capacity, or
 * the task's current CPU is heavily pressured.
 */
static inline int check_misfit_status(struct rq *rq, struct sched_domain *sd)
{
	return rq->misfit_task_load &&
		(rq->cpu_capacity_orig < rq->rd->max_cpu_capacity ||
		 check_cpu_capacity(rq, sd));
}

/*
 * Current decision point for kicking the idle load balancer in the presence
 * of idle CPUs in the system.
 */
static void nohz_balancer_kick(struct rq *rq)
{
	unsigned long now = jiffies;
	struct sched_domain_shared *sds;
	struct sched_domain *sd;
	int nr_busy, i, cpu = rq->cpu;
	unsigned int flags = 0;

	if (unlikely(rq->idle_balance))
		return;

	/*
	 * We may be recently in ticked or tickless idle mode. At the first
	 * busy tick after returning from idle, we will update the busy stats.
	 */
	nohz_balance_exit_idle(rq);

	/*
	 * None are in tickless mode and hence no need for NOHZ idle load
	 * balancing.
	 */
	if (likely(!atomic_read(&nohz.nr_cpus)))
		return;

	if (READ_ONCE(nohz.has_blocked) &&
	    time_after(now, READ_ONCE(nohz.next_blocked)))
		flags = NOHZ_STATS_KICK;

	if (time_before(now, nohz.next_balance))
		goto out;

	if (rq->nr_running >= 2) {
		flags = NOHZ_KICK_MASK;
		goto out;
	}

	rcu_read_lock();

	sd = rcu_dereference(rq->sd);
	if (sd) {
		/*
		 * If there's a CFS task and the current CPU has reduced
		 * capacity; kick the ILB to see if there's a better CPU to run
		 * on.
		 */
		if (rq->cfs.h_nr_running >= 1 && check_cpu_capacity(rq, sd)) {
			flags = NOHZ_KICK_MASK;
			goto unlock;
		}
	}

	sd = rcu_dereference(per_cpu(sd_asym_packing, cpu));
	if (sd) {
		/*
		 * When ASYM_PACKING; see if there's a more preferred CPU
		 * currently idle; in which case, kick the ILB to move tasks
		 * around.
		 */
		for_each_cpu_and(i, sched_domain_span(sd), nohz.idle_cpus_mask) {
			if (sched_asym_prefer(i, cpu)) {
				flags = NOHZ_KICK_MASK;
				goto unlock;
			}
		}
	}

	sd = rcu_dereference(per_cpu(sd_asym_cpucapacity, cpu));
	if (sd) {
		/*
		 * When ASYM_CPUCAPACITY; see if there's a higher capacity CPU
		 * to run the misfit task on.
		 */
		if (check_misfit_status(rq, sd)) {
			flags = NOHZ_KICK_MASK;
			goto unlock;
		}

		/*
		 * For asymmetric systems, we do not want to nicely balance
		 * cache use, instead we want to embrace asymmetry and only
		 * ensure tasks have enough CPU capacity.
		 *
		 * Skip the LLC logic because it's not relevant in that case.
		 */
		goto unlock;
	}

	sds = rcu_dereference(per_cpu(sd_llc_shared, cpu));
	if (sds) {
		/*
		 * If there is an imbalance between LLC domains (IOW we could
		 * increase the overall cache use), we need some less-loaded LLC
		 * domain to pull some load. Likewise, we may need to spread
		 * load within the current LLC domain (e.g. packed SMT cores but
		 * other CPUs are idle). We can't really know from here how busy
		 * the others are - so just get a nohz balance going if it looks
		 * like this LLC domain has tasks we could move.
		 */
		nr_busy = atomic_read(&sds->nr_busy_cpus);
		if (nr_busy > 1) {
			flags = NOHZ_KICK_MASK;
			goto unlock;
		}
	}
unlock:
	rcu_read_unlock();
out:
	if (flags)
		kick_ilb(flags);
}

static void set_cpu_sd_state_busy(int cpu)
{
	struct sched_domain *sd;

	rcu_read_lock();
	sd = rcu_dereference(per_cpu(sd_llc, cpu));

	if (!sd || !sd->nohz_idle)
		goto unlock;
	sd->nohz_idle = 0;

	atomic_inc(&sd->shared->nr_busy_cpus);
unlock:
	rcu_read_unlock();
}

void nohz_balance_exit_idle(struct rq *rq)
{
	SCHED_WARN_ON(rq != this_rq());

	if (likely(!rq->nohz_tick_stopped))
		return;

	rq->nohz_tick_stopped = 0;
	cpumask_clear_cpu(rq->cpu, nohz.idle_cpus_mask);
	atomic_dec(&nohz.nr_cpus);

	set_cpu_sd_state_busy(rq->cpu);
}

static void set_cpu_sd_state_idle(int cpu)
{
	struct sched_domain *sd;

	rcu_read_lock();
	sd = rcu_dereference(per_cpu(sd_llc, cpu));

	if (!sd || sd->nohz_idle)
		goto unlock;
	sd->nohz_idle = 1;

	atomic_dec(&sd->shared->nr_busy_cpus);
unlock:
	rcu_read_unlock();
}

/*
 * This routine will record that the CPU is going idle with tick stopped.
 * This info will be used in performing idle load balancing in the future.
 */
void nohz_balance_enter_idle(int cpu)
{
	struct rq *rq = cpu_rq(cpu);

	SCHED_WARN_ON(cpu != smp_processor_id());

	/* If this CPU is going down, then nothing needs to be done: */
	if (!cpu_active(cpu))
		return;

	/* Spare idle load balancing on CPUs that don't want to be disturbed: */
	if (!housekeeping_cpu(cpu, HK_FLAG_SCHED))
		return;

	/*
	 * Can be set safely without rq->lock held
	 * If a clear happens, it will have evaluated last additions because
	 * rq->lock is held during the check and the clear
	 */
	rq->has_blocked_load = 1;

	/*
	 * The tick is still stopped but load could have been added in the
	 * meantime. We set the nohz.has_blocked flag to trig a check of the
	 * *_avg. The CPU is already part of nohz.idle_cpus_mask so the clear
	 * of nohz.has_blocked can only happen after checking the new load
	 */
	if (rq->nohz_tick_stopped)
		goto out;

	/* If we're a completely isolated CPU, we don't play: */
	if (on_null_domain(rq))
		return;

	rq->nohz_tick_stopped = 1;

	cpumask_set_cpu(cpu, nohz.idle_cpus_mask);
	atomic_inc(&nohz.nr_cpus);

	/*
	 * Ensures that if nohz_idle_balance() fails to observe our
	 * @idle_cpus_mask store, it must observe the @has_blocked
	 * store.
	 */
	smp_mb__after_atomic();

	set_cpu_sd_state_idle(cpu);

out:
	/*
	 * Each time a cpu enter idle, we assume that it has blocked load and
	 * enable the periodic update of the load of idle cpus
	 */
	WRITE_ONCE(nohz.has_blocked, 1);
}

static bool update_nohz_stats(struct rq *rq)
{
	unsigned int cpu = rq->cpu;

	if (!rq->has_blocked_load)
		return false;

	if (!cpumask_test_cpu(cpu, nohz.idle_cpus_mask))
		return false;

	if (!time_after(jiffies, READ_ONCE(rq->last_blocked_load_update_tick)))
		return true;

	update_blocked_averages(cpu);

	return rq->has_blocked_load;
}

static void idle_balance(struct rq *this_rq)
{
	int this_cpu = this_rq->cpu;
	struct rq *src_rq;
	int src_cpu = -1, cpu;
	unsigned int max = 0;
	struct rq_flags src_rf;

	if (IS_CAND_BL_ENABLED) {
		if (idle_pull_global_candidate(this_rq))
			return;
	} else if (IS_GRQ_BL_ENABLED) {
		pull_from_grq(this_rq);
		return;
	} else if (IS_PWR_BL_ENABLED)
		return;

	for_each_online_cpu(cpu) {
		/*
		 * Stop searching for tasks to pull if there are
		 * now runnable tasks on this rq.
		 */
		if (this_rq->nr_running > 0)
			return;

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

	if (src_cpu == -1)
		return;

	src_rq = cpu_rq(src_cpu);

	rq_lock_irqsave(src_rq, &src_rf);
	update_rq_clock(src_rq);

	if (src_rq->nr_running < 2) {
		rq_unlock(src_rq, &src_rf);
		local_irq_restore(src_rf.flags);
	} else {
		move_task(this_rq, src_rq, &src_rf);
	}
}

/*
 * Internal function that runs load balance for all idle cpus. The load balance
 * can be a simple update of blocked load or a complete load balance with
 * tasks movement depending of flags.
 */
static void _nohz_idle_balance(struct rq *this_rq, unsigned int flags,
			       enum cpu_idle_type idle)
{
	/* Earliest time when we have to do rebalance again */
	unsigned long now = jiffies;
	unsigned long next_balance = now + 60*HZ;
	bool has_blocked_load = false;
	int update_next_balance = 0;
	int this_cpu = this_rq->cpu;
	int balance_cpu;
	struct rq *rq;

	SCHED_WARN_ON((flags & NOHZ_KICK_MASK) == NOHZ_BALANCE_KICK);

	/*
	 * We assume there will be no idle load after this update and clear
	 * the has_blocked flag. If a cpu enters idle in the mean time, it will
	 * set the has_blocked flag and trig another update of idle load.
	 * Because a cpu that becomes idle, is added to idle_cpus_mask before
	 * setting the flag, we are sure to not clear the state and not
	 * check the load of an idle cpu.
	 */
	WRITE_ONCE(nohz.has_blocked, 0);

	/*
	 * Ensures that if we miss the CPU, we must see the has_blocked
	 * store from nohz_balance_enter_idle().
	 */
	smp_mb();

	/*
	 * Start with the next CPU after this_cpu so we will end with this_cpu and let a
	 * chance for other idle cpu to pull load.
	 */
	for_each_cpu_wrap(balance_cpu,  nohz.idle_cpus_mask, this_cpu+1) {
		if (!idle_cpu(balance_cpu))
			continue;

		/*
		 * If this CPU gets work to do, stop the load balancing
		 * work being done for other CPUs. Next load
		 * balancing owner will pick it up.
		 */
		if (need_resched()) {
			has_blocked_load = true;
			goto abort;
		}

		rq = cpu_rq(balance_cpu);

		has_blocked_load |= update_nohz_stats(rq);

		/*
		 * If time for next balance is due,
		 * do the balance.
		 */
		if (time_after_eq(jiffies, rq->next_balance)) {
			struct rq_flags rf;

			rq_lock_irqsave(rq, &rf);
			update_rq_clock(rq);
			rq_unlock_irqrestore(rq, &rf);

			if (flags & NOHZ_BALANCE_KICK)
				idle_balance(rq);
		}

		if (time_after(next_balance, rq->next_balance)) {
			next_balance = rq->next_balance;
			update_next_balance = 1;
		}
	}

	/*
	 * next_balance will be updated only when there is a need.
	 * When the CPU is attached to null domain for ex, it will not be
	 * updated.
	 */
	if (likely(update_next_balance))
		nohz.next_balance = next_balance;

	WRITE_ONCE(nohz.next_blocked,
		now + msecs_to_jiffies(LOAD_AVG_PERIOD));

abort:
	/* There is still blocked load, enable periodic update */
	if (has_blocked_load)
		WRITE_ONCE(nohz.has_blocked, 1);
}

/*
 * In CONFIG_NO_HZ_COMMON case, the idle balance kickee will do the
 * rebalancing for all the cpus for whom scheduler ticks are stopped.
 */
static bool nohz_idle_balance(struct rq *this_rq, enum cpu_idle_type idle)
{
	unsigned int flags = this_rq->nohz_idle_balance;

	if (!flags)
		return false;

	this_rq->nohz_idle_balance = 0;

	if (idle != CPU_IDLE)
		return false;

	_nohz_idle_balance(this_rq, flags, idle);

	return true;
}

/*
 * Check if we need to run the ILB for updating blocked load before entering
 * idle state.
 */
void nohz_run_idle_balance(int cpu)
{
	unsigned int flags;

	flags = atomic_fetch_andnot(NOHZ_NEWILB_KICK, nohz_flags(cpu));

	/*
	 * Update the blocked load only if no SCHED_SOFTIRQ is about to happen
	 * (ie NOHZ_STATS_KICK set) and will do the same.
	 */
	if ((flags == NOHZ_NEWILB_KICK) && !need_resched())
		_nohz_idle_balance(cpu_rq(cpu), NOHZ_STATS_KICK, CPU_IDLE);
}

static void nohz_newidle_balance(struct rq *this_rq)
{
	int this_cpu = this_rq->cpu;

	/*
	 * This CPU doesn't want to be disturbed by scheduler
	 * housekeeping
	 */
	if (!housekeeping_cpu(this_cpu, HK_FLAG_SCHED))
		return;

	/* Will wake up very soon. No time for doing anything else*/
	if (this_rq->avg_idle < sysctl_sched_migration_cost)
		return;

	/* Don't need to update blocked load of idle CPUs*/
	if (!READ_ONCE(nohz.has_blocked) ||
	    time_before(jiffies, READ_ONCE(nohz.next_blocked)))
		return;

	/*
	 * Set the need to trigger ILB in order to update blocked load
	 * before entering idle state.
	 */
	atomic_or(NOHZ_NEWILB_KICK, nohz_flags(this_cpu));
}

#else /* !CONFIG_NO_HZ_COMMON */
static inline void nohz_balancer_kick(struct rq *rq) { }

static inline bool nohz_idle_balance(struct rq *this_rq, enum cpu_idle_type idle)
{
	return false;
}

static inline void nohz_newidle_balance(struct rq *this_rq) { }
#endif /* CONFIG_NO_HZ_COMMON */

static void update_curr_lightweight(struct cfs_rq *cfs_rq)
{
	struct sched_entity *curr = cfs_rq->curr;
	struct tt_node *ttn = &curr->tt_node;
	u64 now = sched_clock();
	u64 delta_exec;

	if (!curr)
		return;

	delta_exec = now - curr->exec_start;
	if (unlikely((s64)delta_exec <= 0))
		return;

	curr->exec_start = now;
	curr->sum_exec_runtime += delta_exec;

	ttn->curr_burst += delta_exec;
	ttn->vruntime += convert_to_vruntime(delta_exec, curr);
	cfs_rq->local_cand_hrrn = HRRN_PERCENT(&curr->tt_node, now);
}

static void nohz_try_pull_from_candidate(void)
{
	int cpu;
	struct rq *rq;
	struct cfs_rq *cfs_rq;
#ifdef CONFIG_NO_HZ_FULL
	struct rq_flags rf;
#endif

	/* first, push to grq*/
	for_each_online_cpu(cpu) {
		rq = cpu_rq(cpu);
#ifdef CONFIG_NO_HZ_FULL
		cfs_rq = &rq->cfs;

		if (idle_cpu(cpu) || cfs_rq->nr_running > 1)
			goto out;

		rq_lock_irqsave(rq, &rf);
		update_rq_clock(rq);
		update_curr_lightweight(cfs_rq);
		rq_unlock_irqrestore(rq, &rf);
out:
#endif
		if (idle_cpu(cpu) || !sched_fair_runnable(rq))
			idle_pull_global_candidate(rq);
		else
			active_pull_global_candidate(rq);
	}
}

static int task_can_move_to_grq(struct task_struct *p, struct rq *src_rq)
{
	if (task_running(task_rq(p), p))
		return 0;

	if (kthread_is_per_cpu(p))
		return 0;

	if (is_migration_disabled(p))
		return 0;

	if (p->nr_cpus_allowed <= 1)
		return 0;

	if (task_hot(p, grq, src_rq))
		return 0;

	return 1;
}

void push_to_grq(struct rq *rq)
{
	struct cfs_rq *cfs_rq = &rq->cfs;
	struct sched_entity *se;
	struct tt_node *ttn, *next, *port = NULL;
	struct task_struct *p;
	struct rq_flags rf, grf;

	if (rq == grq)
		return;

	if (!cfs_rq->head)
		return;

	rq_lock_irqsave(rq, &rf);
	update_rq_clock(rq);

	/// dequeue tasks from this rq
	ttn = cfs_rq->head;
	while (ttn) {
		next = ttn->next;

		se = se_of(ttn);
		p = task_of(se);

		if (!task_can_move_to_grq(p, rq))
			goto next;

		// deactivate
		deactivate_task(rq, p, DEQUEUE_NOCLOCK);
		// enqueue to port
		__enqueue_entity_port(&port, se);

		set_task_cpu(p, cpu_of(grq));

next:
		ttn = next;
	}

	rq_unlock_irqrestore(rq, &rf);

	if (!port)
		return;

	LOCK_GRQ(grf);

	/// enqueue tasks to grq
	while (port) {
		se = se_of(port);
		p = task_of(se);
		// enqueue to port
		__dequeue_entity_port(&port, se);

		// activate
		activate_task(grq, p, ENQUEUE_NOCLOCK);
	}

	UNLOCK_GRQ(grf);
}

static int try_pull_from_grq(struct rq *dist_rq)
{
	struct rq_flags rf;
	struct rq_flags grf;
	struct cfs_rq *cfs_rq = &dist_rq->cfs;
	struct sched_entity *se_global = NULL, *se_local = NULL;
	struct task_struct *p = NULL;
	struct tt_node *ttn;

	if (dist_rq == grq)
		return 0;

	/* if no tasks to pull, exit */
	if (!grq->cfs.head)
		return 0;

	rq_lock_irqsave(dist_rq, &rf);
	update_rq_clock(dist_rq);
	se_local = pick_next_entity(cfs_rq, cfs_rq->curr);
	rq_unlock_irqrestore(dist_rq, &rf);

	rq_lock_irqsave(grq, &grf);
	update_rq_clock(grq);
	se_global = pick_next_entity_from_grq(dist_rq, se_local);

	if (se_global == se_local) {
		rq_unlock(grq, &grf);
		local_irq_restore(grf.flags);
		return 0;
	}

	ttn = &se_global->tt_node;
	p = task_of(se_global);

	// detach task
	deactivate_task(grq, p, DEQUEUE_NOCLOCK);
	set_task_cpu(p, cpu_of(dist_rq));

	// unlock src rq
	rq_unlock(grq, &grf);

	// lock dist rq
	rq_lock(dist_rq, &rf);
	update_rq_clock(dist_rq);

	activate_task(dist_rq, p, ENQUEUE_NOCLOCK);
	check_preempt_curr(dist_rq, p, 0);

	// unlock dist rq
	rq_unlock(dist_rq, &rf);
	local_irq_restore(grf.flags);
	return 1;
}

static inline void
update_grq_next_balance(struct rq *rq, int pulled)
{
	/*
	 * if not pulled any, keep eager,
	 * otherwise set next balance
	 */
	if (tt_grq_balance_ms && pulled)
		rq->grq_next_balance = jiffies + msecs_to_jiffies(tt_grq_balance_ms);
}

static void nohz_try_pull_from_grq(void)
{
	int cpu;
	struct rq *rq;
	struct cpumask idle_mask;
	struct cpumask non_idle_mask;
	bool balance_time;
	int pulled = 0;

	cpumask_clear(&non_idle_mask);

	/* first, push to grq*/
	for_each_online_cpu(cpu) {
		if (cpu == 0) continue;
		if (!idle_cpu(cpu)) {
			push_to_grq(cpu_rq(cpu));
			cpumask_set_cpu(cpu, &non_idle_mask);
		} else {
			cpumask_set_cpu(cpu, &idle_mask);
		}
	}

	/* second, idle cpus pull first */
	for_each_cpu(cpu, &idle_mask) {
		if (cpu == 0 || !idle_cpu(cpu))
			continue;

		rq = cpu_rq(cpu);
		pulled = pull_from_grq(rq);
		update_grq_next_balance(rq, pulled);
	}

	/* last, non idle pull */
	for_each_cpu(cpu, &non_idle_mask) {
		rq = cpu_rq(cpu);
		balance_time = time_after_eq(jiffies, rq->grq_next_balance);
		pulled = 0;

		/* mybe it is idle now */
		if (idle_cpu(cpu))
			pulled = pull_from_grq(cpu_rq(cpu));
		else if (tt_grq_balance_ms == 0 || balance_time)
			/* if not idle, try pull every grq_next_balance */
			pulled = try_pull_from_grq(rq);

		update_grq_next_balance(rq, pulled);
	}
}

/*
 * run_rebalance_domains is triggered when needed from the scheduler tick.
 * Also triggered for nohz idle balancing (with nohz_balancing_kick set).
 */
static __latent_entropy void run_rebalance_domains(struct softirq_action *h)
{
	struct rq *this_rq = this_rq();
	enum cpu_idle_type idle = this_rq->idle_balance ?
						CPU_IDLE : CPU_NOT_IDLE;

	/*
	 * If this CPU has a pending nohz_balance_kick, then do the
	 * balancing on behalf of the other idle CPUs whose ticks are
	 * stopped. Do nohz_idle_balance *before* rebalance_domains to
	 * give the idle CPUs a chance to load balance. Else we may
	 * load balance only within the local sched_domain hierarchy
	 * and abort nohz_idle_balance altogether if we pull some load.
	 */
	nohz_idle_balance(this_rq, idle);
}
