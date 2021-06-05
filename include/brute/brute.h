/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BRUTE_H_
#define _BRUTE_H_

#include <linux/sched.h>

#ifdef CONFIG_SECURITY_FORK_BRUTE
bool brute_task_killed(const struct task_struct *task);
#else
static inline bool brute_task_killed(const struct task_struct *task)
{
	return false;
}
#endif

#endif /* _BRUTE_H_ */
