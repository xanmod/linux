
/*
 * After fork, child runs first. If set to 0 (default) then
 * parent will (try to) run first.
 */
unsigned int sysctl_sched_child_runs_first __read_mostly = 1;

const_debug unsigned int sysctl_sched_migration_cost	= 500000UL;

void __init sched_init_granularity(void) {}

#ifdef CONFIG_SMP
/*
 * For asym packing, by default the lower numbered CPU has higher priority.
 */
int __weak arch_asym_cpu_priority(int cpu)
{
	return -cpu;
}

/* Give new sched_entity start runnable values to heavy its load in infant time */
void update_max_interval(void) {}
static int newidle_balance(struct rq *this_rq, struct rq_flags *rf);

static void migrate_task_rq_fair(struct task_struct *p, int new_cpu)
{
#ifdef CONFIG_TT_ACCOUNTING_STATS
	if (p->on_rq == TASK_ON_RQ_MIGRATING) {
		/*
		 * In case of TASK_ON_RQ_MIGRATING we in fact hold the 'old'
		 * rq->lock and can modify state directly.
		 */
		lockdep_assert_rq_held(task_rq(p));
		detach_entity_cfs_rq(&p->se);

	} else {
		/*
		 * We are supposed to update the task to "current" time, then
		 * its up to date and ready to go to new CPU/cfs_rq. But we
		 * have difficulty in getting what current time is, so simply
		 * throw away the out-of-date time. This will result in the
		 * wakee task is less decayed, but giving the wakee more load
		 * sounds not bad.
		 */
		remove_entity_load_avg(&p->se);
	}

	/* We have migrated, no longer consider this task hot */
	p->se.exec_start = 0;
#endif
	/* Tell new CPU we are migrated */
	p->se.avg.last_update_time = 0;

	update_scan_period(p, new_cpu);
}

static void rq_online_fair(struct rq *rq) {}
static void rq_offline_fair(struct rq *rq) {}
static void task_dead_fair(struct task_struct *p)
{
	struct cfs_rq *cfs_rq = cfs_rq_of(&p->se);
	unsigned long flags;

	raw_spin_lock_irqsave(&cfs_rq->removed.lock, flags);
	++cfs_rq->removed.nr;
	raw_spin_unlock_irqrestore(&cfs_rq->removed.lock, flags);
}

#endif /** CONFIG_SMP */

void init_cfs_rq(struct cfs_rq *cfs_rq)
{
	cfs_rq->tasks_timeline = RB_ROOT_CACHED;
#ifdef CONFIG_SMP
	raw_spin_lock_init(&cfs_rq->removed.lock);
#endif
}

#ifdef CONFIG_TT_ACCOUNTING_STATS
static void update_curr(struct cfs_rq *cfs_rq);

static inline void update_load_add(struct load_weight *lw, unsigned long inc)
{
	lw->weight += inc;
	lw->inv_weight = 0;
}

static inline void update_load_sub(struct load_weight *lw, unsigned long dec)
{
	lw->weight -= dec;
	lw->inv_weight = 0;
}

static inline void update_load_set(struct load_weight *lw, unsigned long w)
{
	lw->weight = w;
	lw->inv_weight = 0;
}

static void reweight_entity(struct cfs_rq *cfs_rq, struct sched_entity *se,
			    unsigned long weight)
{
	if (se->on_rq) {
		/* commit outstanding execution time */
		if (cfs_rq->curr == se)
			update_curr(cfs_rq);
		update_load_sub(&cfs_rq->load, se->load.weight);
	}
	dequeue_load_avg(cfs_rq, se);

	update_load_set(&se->load, weight);

#ifdef CONFIG_SMP
	do {
		u32 divider = get_pelt_divider(&se->avg);

		se->avg.load_avg = div_u64(se_weight(se) * se->avg.load_sum, divider);
	} while (0);
#endif

	enqueue_load_avg(cfs_rq, se);
	if (se->on_rq)
		update_load_add(&cfs_rq->load, se->load.weight);

}
#endif

void reweight_task(struct task_struct *p, int prio)
{
#ifdef CONFIG_TT_ACCOUNTING_STATS
	struct sched_entity *se = &p->se;
	struct cfs_rq *cfs_rq = cfs_rq_of(se);
	struct load_weight *load = &se->load;
	unsigned long weight = scale_load(sched_prio_to_weight[prio]);

	reweight_entity(cfs_rq, se, weight);
	load->inv_weight = sched_prio_to_wmult[prio];
#endif
}

static inline struct sched_entity *se_of(struct tt_node *ttn)
{
	return container_of(ttn, struct sched_entity, tt_node);
}

#ifdef CONFIG_SCHED_SMT
DEFINE_STATIC_KEY_FALSE(sched_smt_present);
EXPORT_SYMBOL_GPL(sched_smt_present);

static inline void set_idle_cores(int cpu, int val)
{
	struct sched_domain_shared *sds;

	sds = rcu_dereference(per_cpu(sd_llc_shared, cpu));
	if (sds)
		WRITE_ONCE(sds->has_idle_cores, val);
}

static inline bool test_idle_cores(int cpu, bool def)
{
	struct sched_domain_shared *sds;

	sds = rcu_dereference(per_cpu(sd_llc_shared, cpu));
	if (sds)
		return READ_ONCE(sds->has_idle_cores);

	return def;
}

void __update_idle_core(struct rq *rq)
{
	int core = cpu_of(rq);
	int cpu;

	rcu_read_lock();
	if (test_idle_cores(core, true))
		goto unlock;

	for_each_cpu(cpu, cpu_smt_mask(core)) {
		if (cpu == core)
			continue;

		if (!available_idle_cpu(cpu))
			goto unlock;
	}

	set_idle_cores(core, 1);
unlock:
	rcu_read_unlock();
}
#endif

static void
account_entity_enqueue(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
#ifdef CONFIG_SMP
	struct rq *rq = rq_of(cfs_rq);

	account_numa_enqueue(rq, task_of(se));
	list_add(&se->group_node, &rq->cfs_tasks);
#endif
	cfs_rq->nr_running++;
}

static void
account_entity_dequeue(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
#ifdef CONFIG_SMP
	account_numa_dequeue(rq_of(cfs_rq), task_of(se));
	list_del_init(&se->group_node);
#endif
	cfs_rq->nr_running--;
}


static void
prio_changed_fair(struct rq *rq, struct task_struct *p, int oldprio)
{
	if (!task_on_rq_queued(p))
		return;

	if (rq->cfs.nr_running == 1)
		return;

	/*
	 * Reschedule if we are currently running on this runqueue and
	 * our priority decreased, or if we are not currently running on
	 * this runqueue and our priority is higher than the current's
	 */
	if (task_current(rq, p)) {
		if (p->prio > oldprio)
			resched_curr(rq);
	} else
		check_preempt_curr(rq, p, 0);
}

static void switched_from_fair(struct rq *rq, struct task_struct *p)
{
	detach_task_cfs_rq(p);
}

static void switched_to_fair(struct rq *rq, struct task_struct *p)
{
	attach_task_cfs_rq(p);

	if (task_on_rq_queued(p)) {
		/*
		 * We were most likely switched from sched_rt, so
		 * kick off the schedule if running, otherwise just see
		 * if we can still preempt the current task.
		 */
		if (task_current(rq, p))
			resched_curr(rq);
		else
			check_preempt_curr(rq, p, 0);
	}
}

static unsigned int get_rr_interval_fair(struct rq *rq, struct task_struct *task)
{
	return 0;
}

#ifdef CONFIG_SCHED_DEBUG
#define for_each_leaf_cfs_rq_safe(rq, cfs_rq, pos)	\
		for (cfs_rq = &rq->cfs, pos = NULL; cfs_rq; cfs_rq = pos)

void print_cfs_stats(struct seq_file *m, int cpu)
{
	struct cfs_rq *cfs_rq, *pos;

	rcu_read_lock();
	for_each_leaf_cfs_rq_safe(cpu_rq(cpu), cfs_rq, pos)
		print_cfs_rq(m, cpu, cfs_rq);
	rcu_read_unlock();
}

#ifdef CONFIG_NUMA_BALANCING
void show_numa_stats(struct task_struct *p, struct seq_file *m)
{
	int node;
	unsigned long tsf = 0, tpf = 0, gsf = 0, gpf = 0;
	struct numa_group *ng;

	rcu_read_lock();
	ng = rcu_dereference(p->numa_group);
	for_each_online_node(node) {
		if (p->numa_faults) {
			tsf = p->numa_faults[task_faults_idx(NUMA_MEM, node, 0)];
			tpf = p->numa_faults[task_faults_idx(NUMA_MEM, node, 1)];
		}
		if (ng) {
			gsf = ng->faults[task_faults_idx(NUMA_MEM, node, 0)],
			gpf = ng->faults[task_faults_idx(NUMA_MEM, node, 1)];
		}
		print_numa_stats(m, node, tsf, tpf, gsf, gpf);
	}
	rcu_read_unlock();
}
#endif /* CONFIG_NUMA_BALANCING */
#endif
