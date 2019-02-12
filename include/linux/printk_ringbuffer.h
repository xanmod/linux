/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PRINTK_RINGBUFFER_H
#define _LINUX_PRINTK_RINGBUFFER_H

#include <linux/atomic.h>
#include <linux/percpu.h>

struct prb_cpulock {
	atomic_t owner;
	unsigned long __percpu *irqflags;
};

#define DECLARE_STATIC_PRINTKRB_CPULOCK(name)				\
static DEFINE_PER_CPU(unsigned long, _##name##_percpu_irqflags);	\
static struct prb_cpulock name = {					\
	.owner = ATOMIC_INIT(-1),					\
	.irqflags = &_##name##_percpu_irqflags,				\
}

/* utility functions */
void prb_lock(struct prb_cpulock *cpu_lock, unsigned int *cpu_store);
void prb_unlock(struct prb_cpulock *cpu_lock, unsigned int cpu_store);

#endif /*_LINUX_PRINTK_RINGBUFFER_H */
