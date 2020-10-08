======================================
The Cachy Scheduler by Hamad Al Marri.
======================================

1.  Overview
=============

Cachy scheduler is a CFS-based cpu process scheduler that utilizes CPU cache
and it is based on Highest Response Ratio Next (HRRN) policy.

1.1 About Cachy Scheduler
--------------------------

  - Each CPU has its own runqueue.

  - NORMAL runqueue is a linked list of sched_entities (instead of RB-Tree).

  - RT and other runqueues are just the same as the CFS's.

  - A task gets preempted in every tick if any task has higher HRRN.
    If the clock ticks in 250HZ (i.e. CONFIG_HZ_250=y) then a task
    runs for 4 milliseconds and then got preempted if there are other
    tasks in the runqueue and if any task has higher HRRN.

  - Wake up tasks preempt currently running tasks if its HRRN value is higher.

  - This scheduler is designed for desktop usage since it is about
    responsiveness.

  - Cachy might be good for mobiles or Android since it has high
    responsiveness, but it needs to be integrated to Android, I don't
    think the current version it is ready to go without some tweeking
    and adapting to Android hacks.

1.2. Complexity
----------------

The complexity of Enqueue and Dequeue a task is O(n).

The complexity of pick the next task is in O(1), where n is the number of tasks
in a runqueue (each CPU has its own runqueue).

Note: O(n) sounds scary, but usually for a machine with 4 CPUS where it is used
for desktop or mobile jobs, the maximum number of runnable tasks might not
exceeds 10 (at the pick next run time) - the idle tasks are excluded since they
are dequeued when sleeping and enqueued when they wake up.


2. The Cachy Highest Response Ratio Next (HRRN) policy
=======================================================

Cachy is based in Highest Response Ratio Next (HRRN) policy with some
modifications. HRRN is a scheduling policy in which the process that has the
highest response ratio will run next.

Each process has a response ratio value R = (w_t + s_t) / s_t where w_t is
the process waiting time, and s_t is the process running
time. If two process has similar running times, the
process that has been waiting longer will run first. HRRN aims
to prevent starvation since it strives the waiting time for processes,
and also it increases the response time.

If two processes have the same R after integer rounding, the division remainder
is compared. See below the full
calculation for R value:

	u64 r_curr, r_se, l_curr, l_se;
	u64 vr_curr	= curr->vruntime + 1;
	u64 vr_se	= se->vruntime + 1;
	s64 diff;

	l_curr	= now - curr->hrrn_start_time;
	l_se	= now - se->hrrn_start_time;

	r_curr	= l_curr / vr_curr;
	r_se	= l_se / vr_se;

	diff	= r_se - r_curr;

	// take the remainder if equal
	if (diff == 0) {
		r_curr	= l_curr % vr_curr;
		r_se	= l_se % vr_se;
		diff	= r_se - r_curr;
	}

	if (diff > 0)
		return 1;

	return -1;


2.1 More about HRRN algorithm
------------------------------

The Highest response ratio next (HRRN) scheduling is a non-preemptive
discipline. It was developed by Brinch Hansen as modification of shortest job
next (SJN) to mitigate the problem of process starvation. `Wikipedia <https://en.wikipedia.org/wiki/Highest_response_ratio_next>`_.

The original HRRN is non-preemptive meaning that a task runs until it finishes.
This nature is not good for interactive systems. Applying original HRRN with
preemptive modifications requires two changes.

First, what happens if the scheduler forces a task to preempt every tick? This
can work great for short amount of time lets say (< 60 minutes) until some
tasks ages and new tasks created, then the imbalance happens. Assume one task
T1 (Xorg) is running and waiting for users inputs.

This task will have high HRRN because it sleeps more than it runs, however,
after a long time (say 60 minuets = 3600000000000ns) the life time of T1 is
3600000000000ns lets assume the sum of execution time is 50% = 1800000000000ns.

The HRRN = 3600000000000 / 1800000000000 = 2.
If T1 runs for 4ms, the rate of change on HRRN is too low:
HRRN = 3600000000000 / 1800004000000 = 1.999995556

Also, if T1 waited for 1s HRRN = 3601000000000 / 1800004000000 = 2.00055111,
the rate of change is low too. Both situations are bad, because:

1. A new task T2 will have higher HRRN when it starts, thus it will be picked
instead of T1.

2. The rate of change of T2 compared to T1 is higher.

This situation is not good for infinite processes such as Xorg and desktop
related threads. Those task must run ASAP when they wake up, because they are
related to responsiveness and Interactivity.

Therefore, the original HRRN needs some modifications.


3 HRRN maximum life time
==========================

Instead of calculating a task HRRN value for infinite life time, we proposed
hrrn_max_lifetime which is 10s by default. A task's hrrn_start_time and
hrrn_sum_exec_runtime reset every 10s. Therefore, the rate of change of HRRN
for old and new tasks is normalized. The value hrrn_max_lifetime can be changed
at run time by the following sysctl command:

	sysctl kernel.sched_hrrn_max_lifetime_ms=60000

The value is in milliseconds, the above command changes hrrn_max_lifetime from
10s to 60s.


4. Priorities
==============

The priorities are applied as the followings:
  The vruntime is used in HRRN as the sum of execution time. The vruntime is
  adjusted by CFS based on tasks priorities. The same code fro CFS is used
  in Cachy. The vruntime is equal to sum_exec_runtime if a task has nice value
  of 0 (normal priority). The vruntime will be lower than sum_exec_runtime for
  higher tasks priorities, which make HRRN thinks that those task didn't run
  for much time (compared to their actual run time). The vruntime will be
  higher than sum_exec_runtime for lower tasks priorities, which make HRRN
  thinks that those task ran for much time (compared to their actual run time).
  So priorities are already taken in the acount by using vruntime in the HRRN
  equation instead of actual sum_exec_runtime.


5. Scheduling policies
=======================

Cachy some CFS, implements three scheduling policies:

  - SCHED_NORMAL (traditionally called SCHED_OTHER): The scheduling
    policy that is used for regular tasks.

  - SCHED_BATCH: Does not preempt nearly as often as regular tasks
    would, thereby allowing tasks to run longer and make better use of
    caches but at the cost of interactivity. This is well suited for
    batch jobs.

  - SCHED_IDLE: This is even weaker than nice 19, but its not a true
    idle timer scheduler in order to avoid to get into priority
    inversion problems which would deadlock the machine.

SCHED_FIFO/_RR are implemented in sched/rt.c and are as specified by
POSIX.

The command chrt from util-linux-ng 2.13.1.1 can set all of these except
SCHED_IDLE.
