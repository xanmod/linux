/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_DEADLINE_H
#define _LINUX_SCHED_DEADLINE_H

#include <linux/sched.h>

#ifdef CONFIG_SCHED_PDS

#define __tsk_deadline(p)	((p)->deadline)

static inline int dl_prio(int prio)
{
	return 1;
}

static inline int dl_task(struct task_struct *p)
{
	return 1;
}
#else

#define __tsk_deadline(p)	((p)->dl.deadline)

/*
 * SCHED_DEADLINE tasks has negative priorities, reflecting
 * the fact that any of them has higher prio than RT and
 * NORMAL/BATCH tasks.
 */

#define MAX_DL_PRIO		0

static inline int dl_prio(int prio)
{
	if (unlikely(prio < MAX_DL_PRIO))
		return 1;
	return 0;
}

static inline int dl_task(struct task_struct *p)
{
	return dl_prio(p->prio);
}
#endif /* CONFIG_SCHED_PDS */

static inline bool dl_time_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

#endif /* _LINUX_SCHED_DEADLINE_H */
