/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Kernel support for Wine synchronization primitives
 *
 * Copyright (C) 2021 Zebediah Figura
 */

#ifndef __LINUX_WINESYNC_H
#define __LINUX_WINESYNC_H

#include <linux/types.h>

#define WINESYNC_SEM_GETONWAIT 1

struct winesync_sem_args {
	__s32 sem;
	__u32 count;
	__u32 max;
	__u32 flags;
};

struct winesync_mutex_args {
	__s32 mutex;
	__u32 owner;
	__u32 count;
};

struct winesync_wait_args {
	__u64 timeout;
	__u64 objs;
	__u32 count;
	__u32 owner;
	__u32 index;
	__u32 pad;
};

#define WINESYNC_IOC_BASE 0xf7

#define WINESYNC_IOC_CREATE_SEM		_IOWR(WINESYNC_IOC_BASE, 0, \
					      struct winesync_sem_args)
#define WINESYNC_IOC_DELETE		_IOW (WINESYNC_IOC_BASE, 1, __s32)
#define WINESYNC_IOC_PUT_SEM		_IOWR(WINESYNC_IOC_BASE, 2, \
					      struct winesync_sem_args)
#define WINESYNC_IOC_WAIT_ANY		_IOWR(WINESYNC_IOC_BASE, 3, \
					      struct winesync_wait_args)
#define WINESYNC_IOC_WAIT_ALL		_IOW (WINESYNC_IOC_BASE, 4, \
					      struct winesync_wait_args)
#define WINESYNC_IOC_CREATE_MUTEX	_IOWR(WINESYNC_IOC_BASE, 5, \
					      struct winesync_mutex_args)
#define WINESYNC_IOC_PUT_MUTEX		_IOWR(WINESYNC_IOC_BASE, 6, \
					      struct winesync_mutex_args)
#define WINESYNC_IOC_KILL_OWNER		_IOW (WINESYNC_IOC_BASE, 7, __u32)
#define WINESYNC_IOC_READ_SEM		_IOWR(WINESYNC_IOC_BASE, 8, \
					      struct winesync_sem_args)
#define WINESYNC_IOC_READ_MUTEX		_IOWR(WINESYNC_IOC_BASE, 9, \
					      struct winesync_mutex_args)
#define WINESYNC_IOC_GET_SEM		_IOW (WINESYNC_IOC_BASE, 10, __s32)
#define WINESYNC_IOC_PULSE_SEM		_IOWR(WINESYNC_IOC_BASE, 11, \
					      struct winesync_sem_args)

#endif
