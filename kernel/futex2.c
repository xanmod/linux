// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * futex2 system call interface by André Almeida <andrealmeid@collabora.com>
 *
 * Copyright 2021 Collabora Ltd.
 */

#include <linux/syscalls.h>

#include <linux/freezer.h>
#include <linux/compat.h>
#include <asm/futex.h>

/*
 * Set of flags that futex2 operates. If we got something that is not in this
 * set, it can be a unsupported futex1 operation like BITSET or PI, so we
 * refuse to accept
 */
#define FUTEX2_MASK (FUTEX_SIZE_MASK | FUTEX_SHARED_FLAG | FUTEX_CLOCK_REALTIME)

/* Mask for each futex in futex_waitv list */
#define FUTEXV_WAITER_MASK (FUTEX_SIZE_MASK | FUTEX_SHARED_FLAG)

/* Mask for sys_futex_waitv flag */
#define FUTEXV_MASK (FUTEX_CLOCK_REALTIME)

/**
 * unqueue_multiple() - Remove several futexes from their futex_hash_bucket
 * @q:	The list of futexes to unqueue
 * @count: Number of futexes in the list
 *
 * Helper to unqueue a list of futexes. This can't fail.
 *
 * Return:
 *  - >=0 - Index of the last futex that was awoken;
 *  - -1  - If no futex was awoken
 */
static int unqueue_multiple(struct futex_vector *v, int count)
{
	int ret = -1, i;

	for (i = 0; i < count; i++) {
		if (!unqueue_me(&v[i].q))
			ret = i;
	}

	return ret;
}

/**
 * futex_wait_multiple_setup() - Prepare to wait and enqueue multiple futexes
 * @qs:		The corresponding futex list
 * @count:	The size of the lists
 * @flags:	Futex flags (FLAGS_SHARED, etc.)
 * @awaken:	Index of the last awoken futex
 *
 * Prepare multiple futexes in a single step and enqueue them. This may fail if
 * the futex list is invalid or if any futex was already awoken. On success the
 * task is ready to interruptible sleep.
 *
 * Return:
 *  -  1 - One of the futexes was awaken by another thread
 *  -  0 - Success
 *  - <0 - -EFAULT, -EWOULDBLOCK or -EINVAL
 */
static int futex_wait_multiple_setup(struct futex_vector *vs, int count, int *awaken)
{
	struct futex_hash_bucket *hb;
	int ret, i;
	u32 uval;

	/*
	 * Enqueuing multiple futexes is tricky, because we need to
	 * enqueue each futex in the list before dealing with the next
	 * one to avoid deadlocking on the hash bucket.  But, before
	 * enqueuing, we need to make sure that current->state is
	 * TASK_INTERRUPTIBLE, so we don't absorb any awake events, which
	 * cannot be done before the get_futex_key of the next key,
	 * because it calls get_user_pages, which can sleep.  Thus, we
	 * fetch the list of futexes keys in two steps, by first pinning
	 * all the memory keys in the futex key, and only then we read
	 * each key and queue the corresponding futex.
	 */
retry:
	for (i = 0; i < count; i++) {
		ret = get_futex_key(vs[i].w.uaddr,
				    vs[i].w.flags & FUTEX_SHARED_FLAG,
				    &vs[i].q.key, FUTEX_READ);
		if (unlikely(ret))
			return ret;
	}

	set_current_state(TASK_INTERRUPTIBLE);

	for (i = 0; i < count; i++) {
		struct futex_q *q = &vs[i].q;
		struct futex_waitv *waitv = &vs[i].w;

		hb = queue_lock(q);
		ret = get_futex_value_locked(&uval, waitv->uaddr);
		if (ret) {
			/*
			 * We need to try to handle the fault, which
			 * cannot be done without sleep, so we need to
			 * undo all the work already done, to make sure
			 * we don't miss any wake ups.  Therefore, clean
			 * up, handle the fault and retry from the
			 * beginning.
			 */
			queue_unlock(hb);
			__set_current_state(TASK_RUNNING);

			*awaken = unqueue_multiple(vs, i);
			if (*awaken >= 0)
				return 1;

			if (get_user(uval, (u32 __user *)waitv->uaddr))
				return -EINVAL;

			goto retry;
		}

		if (uval != waitv->val) {
			queue_unlock(hb);
			__set_current_state(TASK_RUNNING);

			/*
			 * If something was already awaken, we can
			 * safely ignore the error and succeed.
			 */
			*awaken = unqueue_multiple(vs, i);
			if (*awaken >= 0)
				return 1;

			return -EWOULDBLOCK;
		}

		/*
		 * The bucket lock can't be held while dealing with the
		 * next futex. Queue each futex at this moment so hb can
		 * be unlocked.
		 */
		queue_me(&vs[i].q, hb);
	}
	return 0;
}

/**
 * futex_wait_multiple() - Prepare to wait on and enqueue several futexes
 * @qs:		The list of futexes to wait on
 * @op:		Operation code from futex's syscall
 * @count:	The number of objects
 * @abs_time:	Timeout before giving up and returning to userspace
 *
 * Entry point for the FUTEX_WAIT_MULTIPLE futex operation, this function
 * sleeps on a group of futexes and returns on the first futex that
 * triggered, or after the timeout has elapsed.
 *
 * Return:
 *  - >=0 - Hint to the futex that was awoken
 *  - <0  - On error
 */
static int futex_wait_multiple(struct futex_vector *qs, unsigned int count,
			       struct hrtimer_sleeper *to)
{
	int ret, hint = 0;
	unsigned int i;

	while (1) {
		ret = futex_wait_multiple_setup(qs, count, &hint);
		if (ret) {
			if (ret > 0) {
				/* A futex was awaken during setup */
				ret = hint;
			}
			return ret;
		}

		if (to)
			hrtimer_start_expires(&to->timer, HRTIMER_MODE_ABS);

		/*
		 * Avoid sleeping if another thread already tried to
		 * wake us.
		 */
		for (i = 0; i < count; i++) {
			if (plist_node_empty(&qs[i].q.list))
				break;
		}

		if (i == count && (!to || to->task))
			freezable_schedule();

		__set_current_state(TASK_RUNNING);

		ret = unqueue_multiple(qs, count);
		if (ret >= 0)
			return ret;

		if (to && !to->task)
			return -ETIMEDOUT;
		else if (signal_pending(current))
			return -ERESTARTSYS;
		/*
		 * The final case is a spurious wakeup, for
		 * which just retry.
		 */
	}
}

#ifdef CONFIG_COMPAT
/**
 * compat_futex_parse_waitv - Parse a waitv array from userspace
 * @futexv:	Kernel side list of waiters to be filled
 * @uwaitv:     Userspace list to be parsed
 * @nr_futexes: Length of futexv
 *
 * Return: Error code on failure, pointer to a prepared futexv otherwise
 */
static int compat_futex_parse_waitv(struct futex_vector *futexv,
				    struct compat_futex_waitv __user *uwaitv,
				    unsigned int nr_futexes)
{
	struct compat_futex_waitv aux;
	unsigned int i;

	for (i = 0; i < nr_futexes; i++) {
		if (copy_from_user(&aux, &uwaitv[i], sizeof(aux)))
			return -EFAULT;

		if ((aux.flags & ~FUTEXV_WAITER_MASK) ||
		    (aux.flags & FUTEX_SIZE_MASK) != FUTEX_32)
			return -EINVAL;

		futexv[i].w.flags = aux.flags;
		futexv[i].w.val = aux.val;
		futexv[i].w.uaddr = compat_ptr(aux.uaddr);
		futexv[i].q = futex_q_init;
	}

	return 0;
}

COMPAT_SYSCALL_DEFINE4(futex_waitv, struct compat_futex_waitv __user *, waiters,
		       unsigned int, nr_futexes, unsigned int, flags,
		       struct __kernel_timespec __user *, timo)
{
	struct hrtimer_sleeper to;
	struct futex_vector *futexv;
	struct timespec64 ts;
	ktime_t time;
	int ret;

	if (flags & ~FUTEXV_MASK)
		return -EINVAL;

	if (!nr_futexes || nr_futexes > FUTEX_WAITV_MAX || !waiters)
		return -EINVAL;

	if (timo) {
		int flag_clkid = 0;

		if (get_timespec64(&ts, timo))
			return -EFAULT;

		if (!timespec64_valid(&ts))
			return -EINVAL;

		if (flags & FUTEX_CLOCK_REALTIME)
			flag_clkid = FLAGS_CLOCKRT;

		time = timespec64_to_ktime(ts);
		futex_setup_timer(&time, &to, flag_clkid, 0);
	}

	futexv = kcalloc(nr_futexes, sizeof(*futexv), GFP_KERNEL);
	if (!futexv)
		return -ENOMEM;

	ret = compat_futex_parse_waitv(futexv, waiters, nr_futexes);
	if (!ret)
		ret = futex_wait_multiple(futexv, nr_futexes, timo ? &to : NULL);

	if (timo) {
		hrtimer_cancel(&to.timer);
		destroy_hrtimer_on_stack(&to.timer);
	}

	kfree(futexv);
	return ret;
}
#endif

static int futex_parse_waitv(struct futex_vector *futexv,
			     struct futex_waitv __user *uwaitv,
			     unsigned int nr_futexes)
{
	struct futex_waitv aux;
	unsigned int i;

	for (i = 0; i < nr_futexes; i++) {
		if (copy_from_user(&aux, &uwaitv[i], sizeof(aux)))
			return -EFAULT;

		if ((aux.flags & ~FUTEXV_WAITER_MASK) ||
		    (aux.flags & FUTEX_SIZE_MASK) != FUTEX_32)
			return -EINVAL;

		futexv[i].w.flags = aux.flags;
		futexv[i].w.val = aux.val;
		futexv[i].w.uaddr = aux.uaddr;
		futexv[i].q = futex_q_init;
	}

	return 0;
}

SYSCALL_DEFINE4(futex_waitv, struct futex_waitv __user *, waiters,
		unsigned int, nr_futexes, unsigned int, flags,
		struct __kernel_timespec __user *, timo)
{
	struct hrtimer_sleeper to;
	struct futex_vector *futexv;
	struct timespec64 ts;
	ktime_t time;
	int ret;

	if (flags & ~FUTEXV_MASK)
		return -EINVAL;

	if (!nr_futexes || nr_futexes > FUTEX_WAITV_MAX || !waiters)
		return -EINVAL;

	if (timo) {
		int flag_clkid = 0;

		if (get_timespec64(&ts, timo))
			return -EFAULT;

		if (!timespec64_valid(&ts))
			return -EINVAL;

		if (flags & FUTEX_CLOCK_REALTIME)
			flag_clkid = FLAGS_CLOCKRT;

		time = timespec64_to_ktime(ts);
		futex_setup_timer(&time, &to, flag_clkid, 0);
	}

	futexv = kcalloc(nr_futexes, sizeof(*futexv), GFP_KERNEL);
	if (!futexv)
		return -ENOMEM;

	ret = futex_parse_waitv(futexv, waiters, nr_futexes);
	if (!ret)
		ret = futex_wait_multiple(futexv, nr_futexes, timo ? &to : NULL);

	if (timo) {
		hrtimer_cancel(&to.timer);
		destroy_hrtimer_on_stack(&to.timer);
	}

	kfree(futexv);
	return ret;
}

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
