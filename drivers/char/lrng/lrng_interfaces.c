// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * LRNG User and kernel space interfaces
 *
 * Copyright (C) 2016 - 2021, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/hw_random.h>
#include <linux/kthread.h>
#include <linux/poll.h>
#include <linux/preempt.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/timex.h>

#define CREATE_TRACE_POINTS
#include <trace/events/random.h>

#include "lrng_internal.h"

/*
 * If the entropy count falls under this number of bits, then we
 * should wake up processes which are selecting or polling on write
 * access to /dev/random.
 */
u32 lrng_write_wakeup_bits = LRNG_WRITE_WAKEUP_ENTROPY;

static LIST_HEAD(lrng_ready_list);
static DEFINE_SPINLOCK(lrng_ready_list_lock);

static DECLARE_WAIT_QUEUE_HEAD(lrng_write_wait);
static DECLARE_WAIT_QUEUE_HEAD(lrng_init_wait);
static struct fasync_struct *fasync;

/********************************** Helper ***********************************/

/* Is the DRNG seed level too low? */
static inline bool lrng_need_entropy(void)
{
	return (lrng_avail_aux_entropy() < lrng_write_wakeup_bits);
}

void lrng_writer_wakeup(void)
{
	if (lrng_need_entropy() && wq_has_sleeper(&lrng_write_wait)) {
		wake_up_interruptible(&lrng_write_wait);
		kill_fasync(&fasync, SIGIO, POLL_OUT);
	}
}

void lrng_init_wakeup(void)
{
	wake_up_all(&lrng_init_wait);
	kill_fasync(&fasync, SIGIO, POLL_IN);
}

/**
 * lrng_process_ready_list() - Ping all kernel internal callers waiting until
 * the DRNG is completely initialized to inform that the DRNG reached that
 * seed level.
 *
 * When the SP800-90B testing is enabled, the ping only happens if the SP800-90B
 * startup health tests are completed. This implies that kernel internal
 * callers always have an SP800-90B compliant noise source when being
 * pinged.
 */
void lrng_process_ready_list(void)
{
	unsigned long flags;
	struct random_ready_callback *rdy, *tmp;

	if (!lrng_state_operational())
		return;

	spin_lock_irqsave(&lrng_ready_list_lock, flags);
	list_for_each_entry_safe(rdy, tmp, &lrng_ready_list, list) {
		struct module *owner = rdy->owner;

		list_del_init(&rdy->list);
		rdy->func(rdy);
		module_put(owner);
	}
	spin_unlock_irqrestore(&lrng_ready_list_lock, flags);
}

void lrng_debug_report_seedlevel(const char *name)
{
#ifdef CONFIG_WARN_ALL_UNSEEDED_RANDOM
	static void *previous = NULL;
	void *caller = (void *) _RET_IP_;

	if (READ_ONCE(previous) == caller)
		return;

	if (!lrng_state_min_seeded())
		pr_notice("%pS %s called without reaching minimally seeded level (available entropy %u)\n",
			  caller, name, lrng_avail_entropy());

	WRITE_ONCE(previous, caller);
#endif
}

/************************ LRNG kernel input interfaces ************************/

/**
 * add_hwgenerator_randomness() - Interface for in-kernel drivers of true
 * hardware RNGs.
 *
 * Those devices may produce endless random bits and will be throttled
 * when our pool is full.
 *
 * @buffer: buffer holding the entropic data from HW noise sources to be used to
 *	    insert into entropy pool.
 * @count: length of buffer
 * @entropy_bits: amount of entropy in buffer (value is in bits)
 */
void add_hwgenerator_randomness(const char *buffer, size_t count,
				size_t entropy_bits)
{
	/*
	 * Suspend writing if we are fully loaded with entropy.
	 * We'll be woken up again once below lrng_write_wakeup_thresh,
	 * or when the calling thread is about to terminate.
	 */
	wait_event_interruptible(lrng_write_wait,
				lrng_need_entropy() ||
				lrng_state_exseed_allow(lrng_noise_source_hw) ||
				kthread_should_stop());
	lrng_state_exseed_set(lrng_noise_source_hw, false);
	lrng_pool_insert_aux(buffer, count, entropy_bits);
}
EXPORT_SYMBOL_GPL(add_hwgenerator_randomness);

/**
 * add_bootloader_randomness() - Handle random seed passed by bootloader.
 *
 * If the seed is trustworthy, it would be regarded as hardware RNGs. Otherwise
 * it would be regarded as device data.
 * The decision is controlled by CONFIG_RANDOM_TRUST_BOOTLOADER.
 *
 * @buf: buffer holding the entropic data from HW noise sources to be used to
 *	 insert into entropy pool.
 * @size: length of buffer
 */
void add_bootloader_randomness(const void *buf, unsigned int size)
{
	lrng_pool_insert_aux(buf, size,
			     IS_ENABLED(CONFIG_RANDOM_TRUST_BOOTLOADER) ?
			     size * 8 : 0);
}
EXPORT_SYMBOL_GPL(add_bootloader_randomness);

/*
 * Callback for HID layer -- use the HID event values to stir the entropy pool
 */
void add_input_randomness(unsigned int type, unsigned int code,
			  unsigned int value)
{
	static unsigned char last_value;

	/* ignore autorepeat and the like */
	if (value == last_value)
		return;

	last_value = value;

	lrng_pcpu_array_add_u32((type << 4) ^ code ^ (code >> 4) ^ value);
}
EXPORT_SYMBOL_GPL(add_input_randomness);

/**
 * add_device_randomness() - Add device- or boot-specific data to the entropy
 * pool to help initialize it.
 *
 * None of this adds any entropy; it is meant to avoid the problem of
 * the entropy pool having similar initial state across largely
 * identical devices.
 *
 * @buf: buffer holding the entropic data from HW noise sources to be used to
 *	 insert into entropy pool.
 * @size: length of buffer
 */
void add_device_randomness(const void *buf, unsigned int size)
{
	lrng_pool_insert_aux((u8 *)buf, size, 0);
}
EXPORT_SYMBOL(add_device_randomness);

#ifdef CONFIG_BLOCK
void rand_initialize_disk(struct gendisk *disk) { }
void add_disk_randomness(struct gendisk *disk) { }
EXPORT_SYMBOL(add_disk_randomness);
#endif

/**
 * del_random_ready_callback() - Delete a previously registered readiness
 * callback function.
 *
 * @rdy: callback definition that was registered initially
 */
void del_random_ready_callback(struct random_ready_callback *rdy)
{
	unsigned long flags;
	struct module *owner = NULL;

	spin_lock_irqsave(&lrng_ready_list_lock, flags);
	if (!list_empty(&rdy->list)) {
		list_del_init(&rdy->list);
		owner = rdy->owner;
	}
	spin_unlock_irqrestore(&lrng_ready_list_lock, flags);

	module_put(owner);
}
EXPORT_SYMBOL(del_random_ready_callback);

/**
 * add_random_ready_callback() - Add a callback function that will be invoked
 * when the DRNG is fully initialized and seeded.
 *
 * @rdy: callback definition to be invoked when the LRNG is seeded
 *
 * Return:
 * * 0 if callback is successfully added
 * * -EALREADY if pool is already initialised (callback not called)
 * * -ENOENT if module for callback is not alive
 */
int add_random_ready_callback(struct random_ready_callback *rdy)
{
	struct module *owner;
	unsigned long flags;
	int err = -EALREADY;

	if (likely(lrng_state_operational()))
		return err;

	owner = rdy->owner;
	if (!try_module_get(owner))
		return -ENOENT;

	spin_lock_irqsave(&lrng_ready_list_lock, flags);
	if (lrng_state_operational())
		goto out;

	owner = NULL;

	list_add(&rdy->list, &lrng_ready_list);
	err = 0;

out:
	spin_unlock_irqrestore(&lrng_ready_list_lock, flags);

	module_put(owner);

	return err;
}
EXPORT_SYMBOL(add_random_ready_callback);

/*********************** LRNG kernel output interfaces ************************/

/**
 * get_random_bytes() - Provider of cryptographic strong random numbers for
 * kernel-internal usage.
 *
 * This function is appropriate for all in-kernel use cases. However,
 * it will always use the ChaCha20 DRNG.
 *
 * @buf: buffer to store the random bytes
 * @nbytes: size of the buffer
 */
void get_random_bytes(void *buf, int nbytes)
{
	lrng_drng_get_atomic((u8 *)buf, (u32)nbytes);
	lrng_debug_report_seedlevel("get_random_bytes");
}
EXPORT_SYMBOL(get_random_bytes);

/**
 * get_random_bytes_full() - Provider of cryptographic strong random numbers
 * for kernel-internal usage.
 *
 * This function is appropriate only for non-atomic use cases as this
 * function may sleep. Though, it provides access to the full functionality
 * of LRNG including the switchable DRNG support, that may support other
 * DRNGs such as the SP800-90A DRBG.
 *
 * @buf: buffer to store the random bytes
 * @nbytes: size of the buffer
 */
void get_random_bytes_full(void *buf, int nbytes)
{
	lrng_drng_get_sleep((u8 *)buf, (u32)nbytes);
	lrng_debug_report_seedlevel("get_random_bytes_full");
}
EXPORT_SYMBOL(get_random_bytes_full);

/**
 * wait_for_random_bytes() - Wait for the LRNG to be seeded and thus
 * guaranteed to supply cryptographically secure random numbers.
 *
 * This applies to: the /dev/urandom device, the get_random_bytes function,
 * and the get_random_{u32,u64,int,long} family of functions. Using any of
 * these functions without first calling this function forfeits the guarantee
 * of security.
 *
 * Return:
 * * 0 if the LRNG has been seeded.
 * * -ERESTARTSYS if the function was interrupted by a signal.
 */
int wait_for_random_bytes(void)
{
	if (likely(lrng_state_min_seeded()))
		return 0;
	return wait_event_interruptible(lrng_init_wait,
					lrng_state_min_seeded());
}
EXPORT_SYMBOL(wait_for_random_bytes);

/**
 * get_random_bytes_arch() - This function will use the architecture-specific
 * hardware random number generator if it is available.
 *
 * The arch-specific hw RNG will almost certainly be faster than what we can
 * do in software, but it is impossible to verify that it is implemented
 * securely (as opposed, to, say, the AES encryption of a sequence number using
 * a key known by the NSA).  So it's useful if we need the speed, but only if
 * we're willing to trust the hardware manufacturer not to have put in a back
 * door.
 *
 * @buf: buffer allocated by caller to store the random data in
 * @nbytes: length of outbuf
 *
 * Return: number of bytes filled in.
 */
int __must_check get_random_bytes_arch(void *buf, int nbytes)
{
	u8 *p = buf;

	while (nbytes) {
		unsigned long v;
		int chunk = min_t(int, nbytes, sizeof(unsigned long));

		if (!arch_get_random_long(&v))
			break;

		memcpy(p, &v, chunk);
		p += chunk;
		nbytes -= chunk;
	}

	if (nbytes)
		lrng_drng_get_atomic((u8 *)p, (u32)nbytes);

	return nbytes;
}
EXPORT_SYMBOL(get_random_bytes_arch);

/*
 * Returns whether or not the LRNG has been seeded.
 *
 * Returns: true if the urandom pool has been seeded.
 *          false if the urandom pool has not been seeded.
 */
bool rng_is_initialized(void)
{
	return lrng_state_operational();
}
EXPORT_SYMBOL(rng_is_initialized);

/************************ LRNG user output interfaces *************************/

static ssize_t lrng_read_common(char __user *buf, size_t nbytes)
{
	ssize_t ret = 0;
	u8 tmpbuf[LRNG_DRNG_BLOCKSIZE] __aligned(LRNG_KCAPI_ALIGN);
	u8 *tmp_large = NULL, *tmp = tmpbuf;
	u32 tmplen = sizeof(tmpbuf);

	if (nbytes == 0)
		return 0;

	/*
	 * Satisfy large read requests -- as the common case are smaller
	 * request sizes, such as 16 or 32 bytes, avoid a kmalloc overhead for
	 * those by using the stack variable of tmpbuf.
	 */
	if (!CONFIG_BASE_SMALL && (nbytes > sizeof(tmpbuf))) {
		tmplen = min_t(u32, nbytes, LRNG_DRNG_MAX_REQSIZE);
		tmp_large = kmalloc(tmplen + LRNG_KCAPI_ALIGN, GFP_KERNEL);
		if (!tmp_large)
			tmplen = sizeof(tmpbuf);
		else
			tmp = PTR_ALIGN(tmp_large, LRNG_KCAPI_ALIGN);
	}

	while (nbytes) {
		u32 todo = min_t(u32, nbytes, tmplen);
		int rc = 0;

		/* Reschedule if we received a large request. */
		if ((tmp_large) && need_resched()) {
			if (signal_pending(current)) {
				if (ret == 0)
					ret = -ERESTARTSYS;
				break;
			}
			schedule();
		}

		rc = lrng_drng_get_sleep(tmp, todo);
		if (rc <= 0) {
			if (rc < 0)
				ret = rc;
			break;
		}
		if (copy_to_user(buf, tmp, rc)) {
			ret = -EFAULT;
			break;
		}

		nbytes -= rc;
		buf += rc;
		ret += rc;
	}

	/* Wipe data just returned from memory */
	if (tmp_large)
		kfree_sensitive(tmp_large);
	else
		memzero_explicit(tmpbuf, sizeof(tmpbuf));

	return ret;
}

static ssize_t
lrng_read_common_block(int nonblock, char __user *buf, size_t nbytes)
{
	if (nbytes == 0)
		return 0;

	if (unlikely(!lrng_state_operational())) {
		int ret;

		if (nonblock)
			return -EAGAIN;

		ret = wait_event_interruptible(lrng_init_wait,
					       lrng_state_operational());
		if (unlikely(ret))
			return ret;
	}

	return lrng_read_common(buf, nbytes);
}

static ssize_t lrng_drng_read_block(struct file *file, char __user *buf,
				     size_t nbytes, loff_t *ppos)
{
	return lrng_read_common_block(file->f_flags & O_NONBLOCK, buf, nbytes);
}

static __poll_t lrng_random_poll(struct file *file, poll_table *wait)
{
	__poll_t mask;

	poll_wait(file, &lrng_init_wait, wait);
	poll_wait(file, &lrng_write_wait, wait);
	mask = 0;
	if (lrng_state_operational())
		mask |= EPOLLIN | EPOLLRDNORM;
	if (lrng_need_entropy() ||
	    lrng_state_exseed_allow(lrng_noise_source_user))
		mask |= EPOLLOUT | EPOLLWRNORM;
	return mask;
}

static ssize_t lrng_drng_write_common(const char __user *buffer, size_t count,
				      u32 entropy_bits)
{
	ssize_t ret = 0;
	u8 buf[64] __aligned(LRNG_KCAPI_ALIGN);
	const char __user *p = buffer;
	u32 orig_entropy_bits = entropy_bits;

	if (!lrng_get_available())
		return -EAGAIN;

	count = min_t(size_t, count, INT_MAX);
	while (count > 0) {
		size_t bytes = min_t(size_t, count, sizeof(buf));
		u32 ent = min_t(u32, bytes<<3, entropy_bits);

		if (copy_from_user(&buf, p, bytes))
			return -EFAULT;
		/* Inject data into entropy pool */
		lrng_pool_insert_aux(buf, bytes, ent);

		count -= bytes;
		p += bytes;
		ret += bytes;
		entropy_bits -= ent;

		cond_resched();
	}

	/* Force reseed of DRNG during next data request. */
	if (!orig_entropy_bits)
		lrng_drng_force_reseed();

	return ret;
}

static ssize_t lrng_drng_read(struct file *file, char __user *buf,
			      size_t nbytes, loff_t *ppos)
{
	if (!lrng_state_min_seeded())
		pr_notice_ratelimited("%s - use of insufficiently seeded DRNG (%zu bytes read)\n",
				      current->comm, nbytes);
	else if (!lrng_state_operational())
		pr_debug_ratelimited("%s - use of not fully seeded DRNG (%zu bytes read)\n",
				     current->comm, nbytes);

	return lrng_read_common(buf, nbytes);
}

static ssize_t lrng_drng_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *ppos)
{
	return lrng_drng_write_common(buffer, count, 0);
}

static long lrng_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	u32 digestsize_bits;
	int size, ent_count_bits;
	int __user *p = (int __user *)arg;

	switch (cmd) {
	case RNDGETENTCNT:
		ent_count_bits = lrng_avail_entropy();
		if (put_user(ent_count_bits, p))
			return -EFAULT;
		return 0;
	case RNDADDTOENTCNT:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (get_user(ent_count_bits, p))
			return -EFAULT;
		ent_count_bits = (int)lrng_avail_aux_entropy() + ent_count_bits;
		if (ent_count_bits < 0)
			ent_count_bits = 0;
		digestsize_bits = lrng_get_digestsize();
		if (ent_count_bits > digestsize_bits)
			ent_count_bits = digestsize_bits;
		lrng_pool_set_entropy(ent_count_bits);
		return 0;
	case RNDADDENTROPY:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (get_user(ent_count_bits, p++))
			return -EFAULT;
		if (ent_count_bits < 0)
			return -EINVAL;
		if (get_user(size, p++))
			return -EFAULT;
		if (size < 0)
			return -EINVAL;
		lrng_state_exseed_set(lrng_noise_source_user, false);
		/* there cannot be more entropy than data */
		ent_count_bits = min(ent_count_bits, size<<3);
		return lrng_drng_write_common((const char __user *)p, size,
					      ent_count_bits);
	case RNDZAPENTCNT:
	case RNDCLEARPOOL:
		/* Clear the entropy pool counter. */
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		lrng_pool_set_entropy(0);
		return 0;
	case RNDRESEEDCRNG:
		/*
		 * We leave the capability check here since it is present
		 * in the upstream's RNG implementation. Yet, user space
		 * can trigger a reseed as easy as writing into /dev/random
		 * or /dev/urandom where no privilege is needed.
		 */
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		/* Force a reseed of all DRNGs */
		lrng_drng_force_reseed();
		return 0;
	default:
		return -EINVAL;
	}
}

static int lrng_fasync(int fd, struct file *filp, int on)
{
	return fasync_helper(fd, filp, on, &fasync);
}

const struct file_operations random_fops = {
	.read  = lrng_drng_read_block,
	.write = lrng_drng_write,
	.poll  = lrng_random_poll,
	.unlocked_ioctl = lrng_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.fasync = lrng_fasync,
	.llseek = noop_llseek,
};

const struct file_operations urandom_fops = {
	.read  = lrng_drng_read,
	.write = lrng_drng_write,
	.unlocked_ioctl = lrng_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.fasync = lrng_fasync,
	.llseek = noop_llseek,
};

SYSCALL_DEFINE3(getrandom, char __user *, buf, size_t, count,
		unsigned int, flags)
{
	if (flags & ~(GRND_NONBLOCK|GRND_RANDOM|GRND_INSECURE))
		return -EINVAL;

	/*
	 * Requesting insecure and blocking randomness at the same time makes
	 * no sense.
	 */
	if ((flags &
	     (GRND_INSECURE|GRND_RANDOM)) == (GRND_INSECURE|GRND_RANDOM))
		return -EINVAL;

	if (count > INT_MAX)
		count = INT_MAX;

	if (flags & GRND_INSECURE)
		return lrng_drng_read(NULL, buf, count, NULL);

	return lrng_read_common_block(flags & GRND_NONBLOCK, buf, count);
}
