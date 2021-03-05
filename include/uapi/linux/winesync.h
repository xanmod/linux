/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Kernel support for Wine synchronization primitives
 *
 * Copyright (C) 2021 Zebediah Figura
 */

#ifndef __LINUX_WINESYNC_H
#define __LINUX_WINESYNC_H

#include <linux/types.h>

struct winesync_sem_args {
	__u32 sem;
	__u32 count;
	__u32 max;
};

#define WINESYNC_IOC_BASE 0xf7

#define WINESYNC_IOC_CREATE_SEM		_IOWR(WINESYNC_IOC_BASE, 0, \
					      struct winesync_sem_args)
#define WINESYNC_IOC_DELETE		_IOW (WINESYNC_IOC_BASE, 1, __u32)
#define WINESYNC_IOC_PUT_SEM		_IOWR(WINESYNC_IOC_BASE, 2, \
					      struct winesync_sem_args)

#endif
