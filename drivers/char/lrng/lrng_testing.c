// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Linux Random Number Generator (LRNG) testing interfaces
 *
 * Copyright (C) 2019 - 2021, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/debugfs.h>
#include <linux/lrng.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <asm/errno.h>

#include "lrng_internal.h"

#define LRNG_TESTING_RINGBUFFER_SIZE	1024
#define LRNG_TESTING_RINGBUFFER_MASK	(LRNG_TESTING_RINGBUFFER_SIZE - 1)

struct lrng_testing {
	u32 lrng_testing_rb[LRNG_TESTING_RINGBUFFER_SIZE];
	u32 rb_reader;
	u32 rb_writer;
	atomic_t lrng_testing_enabled;
	spinlock_t lock;
	wait_queue_head_t read_wait;
};

/*************************** Generic Data Handling ****************************/

/*
 * boot variable:
 * 0 ==> No boot test, gathering of runtime data allowed
 * 1 ==> Boot test enabled and ready for collecting data, gathering runtime
 *	 data is disabled
 * 2 ==> Boot test completed and disabled, gathering of runtime data is
 *	 disabled
 */

static inline void lrng_testing_reset(struct lrng_testing *data)
{
	unsigned long flags;

	spin_lock_irqsave(&data->lock, flags);
	data->rb_reader = 0;
	data->rb_writer = 0;
	spin_unlock_irqrestore(&data->lock, flags);
}

static inline void lrng_testing_init(struct lrng_testing *data, u32 boot)
{
	/*
	 * The boot time testing implies we have a running test. If the
	 * caller wants to clear it, he has to unset the boot_test flag
	 * at runtime via sysfs to enable regular runtime testing
	 */
	if (boot)
		return;

	lrng_testing_reset(data);
	atomic_set(&data->lrng_testing_enabled, 1);
	pr_warn("Enabling data collection\n");
}

static inline void lrng_testing_fini(struct lrng_testing *data, u32 boot)
{
	/* If we have boot data, we do not reset yet to allow data to be read */
	if (boot)
		return;

	atomic_set(&data->lrng_testing_enabled, 0);
	lrng_testing_reset(data);
	pr_warn("Disabling data collection\n");
}

static inline bool lrng_testing_store(struct lrng_testing *data, u32 value,
				      u32 *boot)
{
	unsigned long flags;

	if (!atomic_read(&data->lrng_testing_enabled) && (*boot != 1))
		return false;

	spin_lock_irqsave(&data->lock, flags);

	/*
	 * Disable entropy testing for boot time testing after ring buffer
	 * is filled.
	 */
	if (*boot) {
		if (data->rb_writer > LRNG_TESTING_RINGBUFFER_SIZE) {
			*boot = 2;
			pr_warn_once("One time data collection test disabled\n");
			spin_unlock_irqrestore(&data->lock, flags);
			return false;
		}

		if (data->rb_writer == 1)
			pr_warn("One time data collection test enabled\n");
	}

	data->lrng_testing_rb[data->rb_writer & LRNG_TESTING_RINGBUFFER_MASK] =
									value;
	data->rb_writer++;

	spin_unlock_irqrestore(&data->lock, flags);

	if (wq_has_sleeper(&data->read_wait))
		wake_up_interruptible(&data->read_wait);

	return true;
}

static inline bool lrng_testing_have_data(struct lrng_testing *data)
{
	return ((data->rb_writer & LRNG_TESTING_RINGBUFFER_MASK) !=
		 (data->rb_reader & LRNG_TESTING_RINGBUFFER_MASK));
}

static inline int lrng_testing_reader(struct lrng_testing *data, u32 *boot,
				      u8 *outbuf, u32 outbuflen)
{
	unsigned long flags;
	int collected_data = 0;

	lrng_testing_init(data, *boot);

	while (outbuflen) {
		spin_lock_irqsave(&data->lock, flags);

		/* We have no data or reached the writer. */
		if (!data->rb_writer ||
		    (data->rb_writer == data->rb_reader)) {

			spin_unlock_irqrestore(&data->lock, flags);

			/*
			 * Now we gathered all boot data, enable regular data
			 * collection.
			 */
			if (*boot) {
				*boot = 0;
				goto out;
			}

			wait_event_interruptible(data->read_wait,
						 lrng_testing_have_data(data));
			if (signal_pending(current)) {
				collected_data = -ERESTARTSYS;
				goto out;
			}

			continue;
		}

		/* We copy out word-wise */
		if (outbuflen < sizeof(u32)) {
			spin_unlock_irqrestore(&data->lock, flags);
			goto out;
		}

		memcpy(outbuf, &data->lrng_testing_rb[data->rb_reader],
		       sizeof(u32));
		data->rb_reader++;

		spin_unlock_irqrestore(&data->lock, flags);

		outbuf += sizeof(u32);
		outbuflen -= sizeof(u32);
		collected_data += sizeof(u32);
	}

out:
	lrng_testing_fini(data, *boot);
	return collected_data;
}

static int lrng_testing_extract_user(struct file *file, char __user *buf,
				     size_t nbytes, loff_t *ppos,
				     int (*reader)(u8 *outbuf, u32 outbuflen))
{
	u8 *tmp, *tmp_aligned;
	int ret = 0, large_request = (nbytes > 256);

	if (!nbytes)
		return 0;

	/*
	 * The intention of this interface is for collecting at least
	 * 1000 samples due to the SP800-90B requirements. So, we make no
	 * effort in avoiding allocating more memory that actually needed
	 * by the user. Hence, we allocate sufficient memory to always hold
	 * that amount of data.
	 */
	tmp = kmalloc(LRNG_TESTING_RINGBUFFER_SIZE + sizeof(u32), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	tmp_aligned = PTR_ALIGN(tmp, sizeof(u32));

	while (nbytes) {
		int i;

		if (large_request && need_resched()) {
			if (signal_pending(current)) {
				if (ret == 0)
					ret = -ERESTARTSYS;
				break;
			}
			schedule();
		}

		i = min_t(int, nbytes, LRNG_TESTING_RINGBUFFER_SIZE);
		i = reader(tmp_aligned, i);
		if (i <= 0) {
			if (i < 0)
				ret = i;
			break;
		}
		if (copy_to_user(buf, tmp_aligned, i)) {
			ret = -EFAULT;
			break;
		}

		nbytes -= i;
		buf += i;
		ret += i;
	}

	kfree_sensitive(tmp);

	if (ret > 0)
		*ppos += ret;

	return ret;
}

/************** Raw High-Resolution Timer Entropy Data Handling ***************/

#ifdef CONFIG_LRNG_RAW_HIRES_ENTROPY

static u32 boot_raw_hires_test = 0;
module_param(boot_raw_hires_test, uint, 0644);
MODULE_PARM_DESC(boot_raw_hires_test, "Enable gathering boot time high resolution timer entropy of the first entropy events");

static struct lrng_testing lrng_raw_hires = {
	.rb_reader = 0,
	.rb_writer = 0,
	.lock      = __SPIN_LOCK_UNLOCKED(lrng_raw_hires.lock),
	.read_wait = __WAIT_QUEUE_HEAD_INITIALIZER(lrng_raw_hires.read_wait)
};

bool lrng_raw_hires_entropy_store(u32 value)
{
	return lrng_testing_store(&lrng_raw_hires, value, &boot_raw_hires_test);
}

static int lrng_raw_hires_entropy_reader(u8 *outbuf, u32 outbuflen)
{
	return lrng_testing_reader(&lrng_raw_hires, &boot_raw_hires_test,
				   outbuf, outbuflen);
}

static ssize_t lrng_raw_hires_read(struct file *file, char __user *to,
				   size_t count, loff_t *ppos)
{
	return lrng_testing_extract_user(file, to, count, ppos,
					 lrng_raw_hires_entropy_reader);
}

static const struct file_operations lrng_raw_hires_fops = {
	.owner = THIS_MODULE,
	.read = lrng_raw_hires_read,
};

#endif /* CONFIG_LRNG_RAW_HIRES_ENTROPY */

/********************* Raw Jiffies Entropy Data Handling **********************/

#ifdef CONFIG_LRNG_RAW_JIFFIES_ENTROPY

static u32 boot_raw_jiffies_test = 0;
module_param(boot_raw_jiffies_test, uint, 0644);
MODULE_PARM_DESC(boot_raw_jiffies_test, "Enable gathering boot time high resolution timer entropy of the first entropy events");

static struct lrng_testing lrng_raw_jiffies = {
	.rb_reader = 0,
	.rb_writer = 0,
	.lock      = __SPIN_LOCK_UNLOCKED(lrng_raw_jiffies.lock),
	.read_wait = __WAIT_QUEUE_HEAD_INITIALIZER(lrng_raw_jiffies.read_wait)
};

bool lrng_raw_jiffies_entropy_store(u32 value)
{
	return lrng_testing_store(&lrng_raw_jiffies, value,
				  &boot_raw_jiffies_test);
}

static int lrng_raw_jiffies_entropy_reader(u8 *outbuf, u32 outbuflen)
{
	return lrng_testing_reader(&lrng_raw_jiffies, &boot_raw_jiffies_test,
				   outbuf, outbuflen);
}

static ssize_t lrng_raw_jiffies_read(struct file *file, char __user *to,
				   size_t count, loff_t *ppos)
{
	return lrng_testing_extract_user(file, to, count, ppos,
					 lrng_raw_jiffies_entropy_reader);
}

static const struct file_operations lrng_raw_jiffies_fops = {
	.owner = THIS_MODULE,
	.read = lrng_raw_jiffies_read,
};

#endif /* CONFIG_LRNG_RAW_JIFFIES_ENTROPY */

/************************** Raw IRQ Data Handling ****************************/

#ifdef CONFIG_LRNG_RAW_IRQ_ENTROPY

static u32 boot_raw_irq_test = 0;
module_param(boot_raw_irq_test, uint, 0644);
MODULE_PARM_DESC(boot_raw_irq_test, "Enable gathering boot time entropy of the first IRQ entropy events");

static struct lrng_testing lrng_raw_irq = {
	.rb_reader = 0,
	.rb_writer = 0,
	.lock      = __SPIN_LOCK_UNLOCKED(lrng_raw_irq.lock),
	.read_wait = __WAIT_QUEUE_HEAD_INITIALIZER(lrng_raw_irq.read_wait)
};

bool lrng_raw_irq_entropy_store(u32 value)
{
	return lrng_testing_store(&lrng_raw_irq, value, &boot_raw_irq_test);
}

static int lrng_raw_irq_entropy_reader(u8 *outbuf, u32 outbuflen)
{
	return lrng_testing_reader(&lrng_raw_irq, &boot_raw_irq_test, outbuf,
				   outbuflen);
}

static ssize_t lrng_raw_irq_read(struct file *file, char __user *to,
				 size_t count, loff_t *ppos)
{
	return lrng_testing_extract_user(file, to, count, ppos,
					 lrng_raw_irq_entropy_reader);
}

static const struct file_operations lrng_raw_irq_fops = {
	.owner = THIS_MODULE,
	.read = lrng_raw_irq_read,
};

#endif /* CONFIG_LRNG_RAW_IRQ_ENTROPY */

/************************ Raw IRQFLAGS Data Handling **************************/

#ifdef CONFIG_LRNG_RAW_IRQFLAGS_ENTROPY

static u32 boot_raw_irqflags_test = 0;
module_param(boot_raw_irqflags_test, uint, 0644);
MODULE_PARM_DESC(boot_raw_irqflags_test, "Enable gathering boot time entropy of the first IRQ flags entropy events");

static struct lrng_testing lrng_raw_irqflags = {
	.rb_reader = 0,
	.rb_writer = 0,
	.lock      = __SPIN_LOCK_UNLOCKED(lrng_raw_irqflags.lock),
	.read_wait = __WAIT_QUEUE_HEAD_INITIALIZER(lrng_raw_irqflags.read_wait)
};

bool lrng_raw_irqflags_entropy_store(u32 value)
{
	return lrng_testing_store(&lrng_raw_irqflags, value,
				  &boot_raw_irqflags_test);
}

static int lrng_raw_irqflags_entropy_reader(u8 *outbuf, u32 outbuflen)
{
	return lrng_testing_reader(&lrng_raw_irqflags, &boot_raw_irqflags_test,
				   outbuf, outbuflen);
}

static ssize_t lrng_raw_irqflags_read(struct file *file, char __user *to,
				      size_t count, loff_t *ppos)
{
	return lrng_testing_extract_user(file, to, count, ppos,
					 lrng_raw_irqflags_entropy_reader);
}

static const struct file_operations lrng_raw_irqflags_fops = {
	.owner = THIS_MODULE,
	.read = lrng_raw_irqflags_read,
};

#endif /* CONFIG_LRNG_RAW_IRQFLAGS_ENTROPY */

/************************ Raw _RET_IP_ Data Handling **************************/

#ifdef CONFIG_LRNG_RAW_RETIP_ENTROPY

static u32 boot_raw_retip_test = 0;
module_param(boot_raw_retip_test, uint, 0644);
MODULE_PARM_DESC(boot_raw_retip_test, "Enable gathering boot time entropy of the first return instruction pointer entropy events");

static struct lrng_testing lrng_raw_retip = {
	.rb_reader = 0,
	.rb_writer = 0,
	.lock      = __SPIN_LOCK_UNLOCKED(lrng_raw_retip.lock),
	.read_wait = __WAIT_QUEUE_HEAD_INITIALIZER(lrng_raw_retip.read_wait)
};

bool lrng_raw_retip_entropy_store(u32 value)
{
	return lrng_testing_store(&lrng_raw_retip, value, &boot_raw_retip_test);
}

static int lrng_raw_retip_entropy_reader(u8 *outbuf, u32 outbuflen)
{
	return lrng_testing_reader(&lrng_raw_retip, &boot_raw_retip_test,
				   outbuf, outbuflen);
}

static ssize_t lrng_raw_retip_read(struct file *file, char __user *to,
				   size_t count, loff_t *ppos)
{
	return lrng_testing_extract_user(file, to, count, ppos,
					 lrng_raw_retip_entropy_reader);
}

static const struct file_operations lrng_raw_retip_fops = {
	.owner = THIS_MODULE,
	.read = lrng_raw_retip_read,
};

#endif /* CONFIG_LRNG_RAW_RETIP_ENTROPY */

/********************** Raw IRQ register Data Handling ************************/

#ifdef CONFIG_LRNG_RAW_REGS_ENTROPY

static u32 boot_raw_regs_test = 0;
module_param(boot_raw_regs_test, uint, 0644);
MODULE_PARM_DESC(boot_raw_regs_test, "Enable gathering boot time entropy of the first interrupt register entropy events");

static struct lrng_testing lrng_raw_regs = {
	.rb_reader = 0,
	.rb_writer = 0,
	.lock      = __SPIN_LOCK_UNLOCKED(lrng_raw_regs.lock),
	.read_wait = __WAIT_QUEUE_HEAD_INITIALIZER(lrng_raw_regs.read_wait)
};

bool lrng_raw_regs_entropy_store(u32 value)
{
	return lrng_testing_store(&lrng_raw_regs, value, &boot_raw_regs_test);
}

static int lrng_raw_regs_entropy_reader(u8 *outbuf, u32 outbuflen)
{
	return lrng_testing_reader(&lrng_raw_regs, &boot_raw_regs_test,
				   outbuf, outbuflen);
}

static ssize_t lrng_raw_regs_read(struct file *file, char __user *to,
				  size_t count, loff_t *ppos)
{
	return lrng_testing_extract_user(file, to, count, ppos,
					 lrng_raw_regs_entropy_reader);
}

static const struct file_operations lrng_raw_regs_fops = {
	.owner = THIS_MODULE,
	.read = lrng_raw_regs_read,
};

#endif /* CONFIG_LRNG_RAW_REGS_ENTROPY */

/********************** Raw Entropy Array Data Handling ***********************/

#ifdef CONFIG_LRNG_RAW_ARRAY

static u32 boot_raw_array = 0;
module_param(boot_raw_array, uint, 0644);
MODULE_PARM_DESC(boot_raw_array, "Enable gathering boot time raw noise array data of the first entropy events");

static struct lrng_testing lrng_raw_array = {
	.rb_reader = 0,
	.rb_writer = 0,
	.lock      = __SPIN_LOCK_UNLOCKED(lrng_raw_array.lock),
	.read_wait = __WAIT_QUEUE_HEAD_INITIALIZER(lrng_raw_array.read_wait)
};

bool lrng_raw_array_entropy_store(u32 value)
{
	return lrng_testing_store(&lrng_raw_array, value, &boot_raw_array);
}

static int lrng_raw_array_entropy_reader(u8 *outbuf, u32 outbuflen)
{
	return lrng_testing_reader(&lrng_raw_array, &boot_raw_array, outbuf,
				   outbuflen);
}

static ssize_t lrng_raw_array_read(struct file *file, char __user *to,
				   size_t count, loff_t *ppos)
{
	return lrng_testing_extract_user(file, to, count, ppos,
					 lrng_raw_array_entropy_reader);
}

static const struct file_operations lrng_raw_array_fops = {
	.owner = THIS_MODULE,
	.read = lrng_raw_array_read,
};

#endif /* CONFIG_LRNG_RAW_ARRAY */

/******************** Interrupt Performance Data Handling *********************/

#ifdef CONFIG_LRNG_IRQ_PERF

static u32 boot_irq_perf = 0;
module_param(boot_irq_perf, uint, 0644);
MODULE_PARM_DESC(boot_irq_perf, "Enable gathering boot time interrupt performance data of the first entropy events");

static struct lrng_testing lrng_irq_perf = {
	.rb_reader = 0,
	.rb_writer = 0,
	.lock      = __SPIN_LOCK_UNLOCKED(lrng_irq_perf.lock),
	.read_wait = __WAIT_QUEUE_HEAD_INITIALIZER(lrng_irq_perf.read_wait)
};

bool lrng_perf_time(u32 start)
{
	return lrng_testing_store(&lrng_irq_perf, random_get_entropy() - start,
				  &boot_irq_perf);
}

static int lrng_irq_perf_reader(u8 *outbuf, u32 outbuflen)
{
	return lrng_testing_reader(&lrng_irq_perf, &boot_irq_perf, outbuf,
				   outbuflen);
}

static ssize_t lrng_irq_perf_read(struct file *file, char __user *to,
				  size_t count, loff_t *ppos)
{
	return lrng_testing_extract_user(file, to, count, ppos,
					 lrng_irq_perf_reader);
}

static const struct file_operations lrng_irq_perf_fops = {
	.owner = THIS_MODULE,
	.read = lrng_irq_perf_read,
};

#endif /* CONFIG_LRNG_IRQ_PERF */

/*********************************** ACVT ************************************/

#ifdef CONFIG_LRNG_ACVT_HASH

/* maximum amount of data to be hashed as defined by ACVP */
#define LRNG_ACVT_MAX_SHA_MSG	(65536 >> 3)

/*
 * As we use static variables to store the data, it is clear that the
 * test interface is only able to handle single threaded testing. This is
 * considered to be sufficient for testing. If multi-threaded use of the
 * ACVT test interface would be performed, the caller would get garbage
 * but the kernel operation is unaffected by this.
 */
static u8 lrng_acvt_hash_data[LRNG_ACVT_MAX_SHA_MSG]
						__aligned(LRNG_KCAPI_ALIGN);
static atomic_t lrng_acvt_hash_data_size = ATOMIC_INIT(0);
static u8 lrng_acvt_hash_digest[LRNG_ATOMIC_DIGEST_SIZE];

static ssize_t lrng_acvt_hash_write(struct file *file, const char __user *buf,
				    size_t nbytes, loff_t *ppos)
{
	if (nbytes > LRNG_ACVT_MAX_SHA_MSG)
		return -EINVAL;

	atomic_set(&lrng_acvt_hash_data_size, (int)nbytes);

	return simple_write_to_buffer(lrng_acvt_hash_data,
				      LRNG_ACVT_MAX_SHA_MSG, ppos, buf, nbytes);
}

static ssize_t lrng_acvt_hash_read(struct file *file, char __user *to,
				   size_t count, loff_t *ppos)
{
	SHASH_DESC_ON_STACK(shash, NULL);
	const struct lrng_crypto_cb *crypto_cb = &lrng_cc20_crypto_cb;
	ssize_t ret;

	if (count > LRNG_ATOMIC_DIGEST_SIZE)
		return -EINVAL;

	ret = crypto_cb->lrng_hash_init(shash, NULL) ?:
	      crypto_cb->lrng_hash_update(shash, lrng_acvt_hash_data,
				atomic_read_u32(&lrng_acvt_hash_data_size)) ?:
	      crypto_cb->lrng_hash_final(shash, lrng_acvt_hash_digest);
	if (ret)
		return ret;

	return simple_read_from_buffer(to, count, ppos, lrng_acvt_hash_digest,
				       sizeof(lrng_acvt_hash_digest));
}

static const struct file_operations lrng_acvt_hash_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.llseek = default_llseek,
	.read = lrng_acvt_hash_read,
	.write = lrng_acvt_hash_write,
};

#endif /* CONFIG_LRNG_ACVT_DRNG */

/**************************************************************************
 * Debugfs interface
 **************************************************************************/

static int __init lrng_raw_init(void)
{
	struct dentry *lrng_raw_debugfs_root;

	lrng_raw_debugfs_root = debugfs_create_dir(KBUILD_MODNAME, NULL);

#ifdef CONFIG_LRNG_RAW_HIRES_ENTROPY
	debugfs_create_file_unsafe("lrng_raw_hires", 0400,
				   lrng_raw_debugfs_root, NULL,
				   &lrng_raw_hires_fops);
#endif
#ifdef CONFIG_LRNG_RAW_JIFFIES_ENTROPY
	debugfs_create_file_unsafe("lrng_raw_jiffies", 0400,
				   lrng_raw_debugfs_root, NULL,
				   &lrng_raw_jiffies_fops);
#endif
#ifdef CONFIG_LRNG_RAW_IRQ_ENTROPY
	debugfs_create_file_unsafe("lrng_raw_irq", 0400, lrng_raw_debugfs_root,
				   NULL, &lrng_raw_irq_fops);
#endif
#ifdef CONFIG_LRNG_RAW_IRQFLAGS_ENTROPY
	debugfs_create_file_unsafe("lrng_raw_irqflags", 0400,
				   lrng_raw_debugfs_root, NULL,
				   &lrng_raw_irqflags_fops);
#endif
#ifdef CONFIG_LRNG_RAW_RETIP_ENTROPY
	debugfs_create_file_unsafe("lrng_raw_retip", 0400,
				   lrng_raw_debugfs_root, NULL,
				   &lrng_raw_retip_fops);
#endif
#ifdef CONFIG_LRNG_RAW_REGS_ENTROPY
	debugfs_create_file_unsafe("lrng_raw_regs", 0400,
				   lrng_raw_debugfs_root, NULL,
				   &lrng_raw_regs_fops);
#endif
#ifdef CONFIG_LRNG_RAW_ARRAY
	debugfs_create_file_unsafe("lrng_raw_array", 0400,
				   lrng_raw_debugfs_root, NULL,
				   &lrng_raw_array_fops);
#endif
#ifdef CONFIG_LRNG_IRQ_PERF
	debugfs_create_file_unsafe("lrng_irq_perf", 0400, lrng_raw_debugfs_root,
				   NULL, &lrng_irq_perf_fops);
#endif
#ifdef CONFIG_LRNG_ACVT_HASH
	debugfs_create_file_unsafe("lrng_acvt_hash", 0600,
				   lrng_raw_debugfs_root, NULL,
				   &lrng_acvt_hash_fops);
#endif

	return 0;
}

module_init(lrng_raw_init);
