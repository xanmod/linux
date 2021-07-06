// SPDX-License-Identifier: GPL-2.0-only
#ifndef _LINUX_RW_BASE_RT_H
#define _LINUX_RW_BASE_RT_H

#include <linux/rtmutex.h>
#include <linux/atomic.h>

#define READER_BIAS		(1U << 31)
#define WRITER_BIAS		(1U << 30)

struct rwbase_rt {
	atomic_t		readers;
	struct rt_mutex		rtmutex;
};

#define __RWBASE_INITIALIZER(name)				\
{								\
	.readers = ATOMIC_INIT(READER_BIAS),			\
	.rtmutex = __RT_MUTEX_INITIALIZER(name.rtmutex),	\
}

#define init_rwbase_rt(rwbase)					\
	do {							\
	rt_mutex_init(&(rwbase)->rtmutex);			\
	atomic_set(&(rwbase)->readers, READER_BIAS);		\
} while (0)

static __always_inline bool rw_base_is_locked(struct rwbase_rt *rwb)
{
	return atomic_read(&rwb->readers) != READER_BIAS;
}

static __always_inline bool rw_base_is_contended(struct rwbase_rt *rwb)
{
	return atomic_read(&rwb->readers) > 0;
}
#endif
