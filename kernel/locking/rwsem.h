/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __INTERNAL_RWSEM_H
#define __INTERNAL_RWSEM_H
#include <linux/rwsem.h>

#ifndef CONFIG_PREEMPT_RT
extern void __down_read(struct rw_semaphore *sem);
extern void __up_read(struct rw_semaphore *sem);
#endif

#endif /* __INTERNAL_RWSEM_H */
