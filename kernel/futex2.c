// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * futex2 system call interface by André Almeida <andrealmeid@collabora.com>
 *
 * Copyright 2021 Collabora Ltd.
 */

#include <linux/syscalls.h>

#include <asm/futex.h>

/*
 * Set of flags that futex2 operates. If we got something that is not in this
 * set, it can be a unsupported futex1 operation like BITSET or PI, so we
 * refuse to accept
 */
#define FUTEX2_MASK (FUTEX_SIZE_MASK | FUTEX_SHARED_FLAG | FUTEX_CLOCK_REALTIME)

static long ksys_futex_wait(void __user *uaddr, u64 val, unsigned int flags,
			    struct __kernel_timespec __user *timo)
{
	unsigned int size = flags & FUTEX_SIZE_MASK, futex_flags = 0;
	ktime_t *kt = NULL, time;
	struct timespec64 ts;

	if (flags & ~FUTEX2_MASK)
		return -EINVAL;

	if (flags & FUTEX_SHARED_FLAG)
		futex_flags |= FLAGS_SHARED;

	if (flags & FUTEX_CLOCK_REALTIME)
		futex_flags |= FLAGS_CLOCKRT;

	if (size != FUTEX_32)
		return -EINVAL;

	if (timo) {
		if (get_timespec64(&ts, timo))
			return -EFAULT;

		if (!timespec64_valid(&ts))
			return -EINVAL;

		time = timespec64_to_ktime(ts);
		kt = &time;
	}

	return futex_wait(uaddr, futex_flags, val, kt, FUTEX_BITSET_MATCH_ANY);
}

SYSCALL_DEFINE4(futex_wait, void __user *, uaddr, u64, val, unsigned int, flags,
		struct __kernel_timespec __user *, timo)
{
	return ksys_futex_wait(uaddr, val, flags, timo);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(compat_futex_wait, void __user *, uaddr, compat_u64, val,
		       unsigned int, flags,
		       struct __kernel_timespec __user *, timo)
{
	return ksys_futex_wait(uaddr, val, flags, timo);
}
#endif

SYSCALL_DEFINE3(futex_wake, void __user *, uaddr, unsigned int, nr_wake,
		unsigned int, flags)
{
	unsigned int size = flags & FUTEX_SIZE_MASK, futex_flags = 0;

	if (flags & ~FUTEX2_MASK)
		return -EINVAL;

	if (flags & FUTEX_SHARED_FLAG)
		futex_flags |= FLAGS_SHARED;

	if (size != FUTEX_32)
		return -EINVAL;

	return futex_wake(uaddr, futex_flags, nr_wake, FUTEX_BITSET_MATCH_ANY);
}
