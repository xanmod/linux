/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PRINTK_RINGBUFFER_H
#define _LINUX_PRINTK_RINGBUFFER_H

#include <linux/atomic.h>
#include <linux/percpu.h>

struct prb_cpulock {
	atomic_t owner;
	unsigned long __percpu *irqflags;
};

struct printk_ringbuffer {
	void *buffer;
	unsigned int size_bits;

	u64 seq;

	atomic_long_t tail;
	atomic_long_t head;
	atomic_long_t reserve;

	struct prb_cpulock *cpulock;
	atomic_t ctx;
};

struct prb_entry {
	unsigned int size;
	u64 seq;
	char data[0];
};

struct prb_handle {
	struct printk_ringbuffer *rb;
	unsigned int cpu;
	struct prb_entry *entry;
};

#define DECLARE_STATIC_PRINTKRB_CPULOCK(name)				\
static DEFINE_PER_CPU(unsigned long, _##name##_percpu_irqflags);	\
static struct prb_cpulock name = {					\
	.owner = ATOMIC_INIT(-1),					\
	.irqflags = &_##name##_percpu_irqflags,				\
}

#define DECLARE_STATIC_PRINTKRB(name, szbits, cpulockptr)		\
static char _##name##_buffer[1 << (szbits)]				\
	__aligned(__alignof__(long));					\
static struct printk_ringbuffer name = {				\
	.buffer = &_##name##_buffer[0],					\
	.size_bits = szbits,						\
	.seq = 0,							\
	.tail = ATOMIC_LONG_INIT(-111 * sizeof(long)),			\
	.head = ATOMIC_LONG_INIT(-111 * sizeof(long)),			\
	.reserve = ATOMIC_LONG_INIT(-111 * sizeof(long)),		\
	.cpulock = cpulockptr,						\
	.ctx = ATOMIC_INIT(0),						\
}

/* writer interface */
char *prb_reserve(struct prb_handle *h, struct printk_ringbuffer *rb,
		  unsigned int size);
void prb_commit(struct prb_handle *h);

/* utility functions */
void prb_lock(struct prb_cpulock *cpu_lock, unsigned int *cpu_store);
void prb_unlock(struct prb_cpulock *cpu_lock, unsigned int cpu_store);

#endif /*_LINUX_PRINTK_RINGBUFFER_H */
