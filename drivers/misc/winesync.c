// SPDX-License-Identifier: GPL-2.0-only
/*
 * winesync.c - Kernel driver for Wine synchronization primitives
 *
 * Copyright (C) 2021 Zebediah Figura
 */

#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/xarray.h>
#include <uapi/linux/winesync.h>

#define WINESYNC_NAME	"winesync"

enum winesync_type {
	WINESYNC_TYPE_SEM,
};

struct winesync_obj {
	struct rcu_head rhead;
	struct kref refcount;
	spinlock_t lock;

	struct list_head any_waiters;

	enum winesync_type type;

	/* The following fields are protected by the object lock. */
	union {
		struct {
			__u32 count;
			__u32 max;
		} sem;
	} u;
};

struct winesync_q_entry {
	struct list_head node;
	struct winesync_q *q;
	struct winesync_obj *obj;
	__u32 index;
};

struct winesync_q {
	struct task_struct *task;
	__u32 owner;

	/*
	 * Protected via atomic_cmpxchg(). Only the thread that wins the
	 * compare-and-swap may actually change object states and wake this
	 * task.
	 */
	atomic_t signaled;

	__u32 count;
	struct winesync_q_entry entries[];
};

struct winesync_device {
	struct xarray objects;
};

static struct winesync_obj *get_obj(struct winesync_device *dev, __u32 id)
{
	struct winesync_obj *obj;

	rcu_read_lock();
	obj = xa_load(&dev->objects, id);
	if (obj && !kref_get_unless_zero(&obj->refcount))
		obj = NULL;
	rcu_read_unlock();

	return obj;
}

static void destroy_obj(struct kref *ref)
{
	struct winesync_obj *obj = container_of(ref, struct winesync_obj, refcount);

	kfree_rcu(obj, rhead);
}

static void put_obj(struct winesync_obj *obj)
{
	kref_put(&obj->refcount, destroy_obj);
}

static struct winesync_obj *get_obj_typed(struct winesync_device *dev, __u32 id,
					  enum winesync_type type)
{
	struct winesync_obj *obj = get_obj(dev, id);

	if (obj && obj->type != type) {
		put_obj(obj);
		return NULL;
	}
	return obj;
}

static int winesync_char_open(struct inode *inode, struct file *file)
{
	struct winesync_device *dev;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	xa_init_flags(&dev->objects, XA_FLAGS_ALLOC);

	file->private_data = dev;
	return nonseekable_open(inode, file);
}

static int winesync_char_release(struct inode *inode, struct file *file)
{
	struct winesync_device *dev = file->private_data;
	struct winesync_obj *obj;
	unsigned long id;

	xa_for_each(&dev->objects, id, obj)
		put_obj(obj);

	xa_destroy(&dev->objects);

	kfree(dev);

	return 0;
}

static void init_obj(struct winesync_obj *obj)
{
	kref_init(&obj->refcount);
	spin_lock_init(&obj->lock);
	INIT_LIST_HEAD(&obj->any_waiters);
}

static void try_wake_any_sem(struct winesync_obj *sem)
{
	struct winesync_q_entry *entry;

	lockdep_assert_held(&sem->lock);

	list_for_each_entry(entry, &sem->any_waiters, node) {
		struct winesync_q *q = entry->q;

		if (!sem->u.sem.count)
			break;

		if (atomic_cmpxchg(&q->signaled, -1, entry->index) == -1) {
			sem->u.sem.count--;
			wake_up_process(q->task);
		}
	}
}

static int winesync_create_sem(struct winesync_device *dev, void __user *argp)
{
	struct winesync_sem_args __user *user_args = argp;
	struct winesync_sem_args args;
	struct winesync_obj *sem;
	__u32 id;
	int ret;

	if (copy_from_user(&args, argp, sizeof(args)))
		return -EFAULT;

	if (args.count > args.max)
		return -EINVAL;

	sem = kzalloc(sizeof(*sem), GFP_KERNEL);
	if (!sem)
		return -ENOMEM;

	init_obj(sem);
	sem->type = WINESYNC_TYPE_SEM;
	sem->u.sem.count = args.count;
	sem->u.sem.max = args.max;

	ret = xa_alloc(&dev->objects, &id, sem, xa_limit_32b, GFP_KERNEL);
	if (ret < 0) {
		kfree(sem);
		return ret;
	}

	return put_user(id, &user_args->sem);
}

static int winesync_delete(struct winesync_device *dev, void __user *argp)
{
	struct winesync_obj *obj;
	__u32 id;

	if (get_user(id, (__u32 __user *)argp))
		return -EFAULT;

	obj = xa_erase(&dev->objects, id);
	if (!obj)
		return -EINVAL;

	put_obj(obj);
	return 0;
}

/*
 * Actually change the semaphore state, returning -EOVERFLOW if it is made
 * invalid.
 */
static int put_sem_state(struct winesync_obj *sem, __u32 count)
{
	lockdep_assert_held(&sem->lock);

	if (sem->u.sem.count + count < sem->u.sem.count ||
	    sem->u.sem.count + count > sem->u.sem.max)
		return -EOVERFLOW;

	sem->u.sem.count += count;
	return 0;
}

static int winesync_put_sem(struct winesync_device *dev, void __user *argp)
{
	struct winesync_sem_args __user *user_args = argp;
	struct winesync_sem_args args;
	struct winesync_obj *sem;
	__u32 prev_count;
	int ret;

	if (copy_from_user(&args, argp, sizeof(args)))
		return -EFAULT;

	sem = get_obj_typed(dev, args.sem, WINESYNC_TYPE_SEM);
	if (!sem)
		return -EINVAL;

	spin_lock(&sem->lock);

	prev_count = sem->u.sem.count;
	ret = put_sem_state(sem, args.count);
	if (!ret)
		try_wake_any_sem(sem);

	spin_unlock(&sem->lock);

	put_obj(sem);

	if (!ret && put_user(prev_count, &user_args->count))
		ret = -EFAULT;

	return ret;
}

static int winesync_schedule(const struct winesync_q *q, ktime_t *timeout)
{
	int ret = 0;

	do {
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}

		set_current_state(TASK_INTERRUPTIBLE);
		if (atomic_read(&q->signaled) != -1) {
			ret = 0;
			break;
		}
		ret = schedule_hrtimeout(timeout, HRTIMER_MODE_ABS);
	} while (ret < 0);
	__set_current_state(TASK_RUNNING);

	return ret;
}

/*
 * Allocate and initialize the winesync_q structure, but do not queue us yet.
 * Also, calculate the relative timeout.
 */
static int setup_wait(struct winesync_device *dev,
		      const struct winesync_wait_args *args,
		      ktime_t *ret_timeout, struct winesync_q **ret_q)
{
	const __u32 count = args->count;
	struct winesync_q *q;
	ktime_t timeout = 0;
	__u32 *ids;
	__u32 i, j;

	if (!args->owner || args->pad)
		return -EINVAL;

	if (args->timeout) {
		struct timespec64 to;

		if (get_timespec64(&to, u64_to_user_ptr(args->timeout)))
			return -EFAULT;
		if (!timespec64_valid(&to))
			return -EINVAL;

		timeout = timespec64_to_ns(&to);
	}

	ids = kmalloc_array(count, sizeof(*ids), GFP_KERNEL);
	if (!ids)
		return -ENOMEM;
	if (copy_from_user(ids, u64_to_user_ptr(args->objs),
			   array_size(count, sizeof(*ids)))) {
		kfree(ids);
		return -EFAULT;
	}

	q = kmalloc(struct_size(q, entries, count), GFP_KERNEL);
	if (!q) {
		kfree(ids);
		return -ENOMEM;
	}
	q->task = current;
	q->owner = args->owner;
	atomic_set(&q->signaled, -1);
	q->count = count;

	for (i = 0; i < count; i++) {
		struct winesync_q_entry *entry = &q->entries[i];
		struct winesync_obj *obj = get_obj(dev, ids[i]);

		if (!obj)
			goto err;

		entry->obj = obj;
		entry->q = q;
		entry->index = i;
	}

	kfree(ids);

	*ret_q = q;
	*ret_timeout = timeout;
	return 0;

err:
	for (j = 0; j < i; j++)
		put_obj(q->entries[j].obj);
	kfree(ids);
	kfree(q);
	return -EINVAL;
}

static void try_wake_any_obj(struct winesync_obj *obj)
{
	switch (obj->type) {
	case WINESYNC_TYPE_SEM:
		try_wake_any_sem(obj);
		break;
	}
}

static int winesync_wait_any(struct winesync_device *dev, void __user *argp)
{
	struct winesync_wait_args args;
	struct winesync_q *q;
	ktime_t timeout;
	int signaled;
	__u32 i;
	int ret;

	if (copy_from_user(&args, argp, sizeof(args)))
		return -EFAULT;

	ret = setup_wait(dev, &args, &timeout, &q);
	if (ret < 0)
		return ret;

	/* queue ourselves */

	for (i = 0; i < args.count; i++) {
		struct winesync_q_entry *entry = &q->entries[i];
		struct winesync_obj *obj = entry->obj;

		spin_lock(&obj->lock);
		list_add_tail(&entry->node, &obj->any_waiters);
		spin_unlock(&obj->lock);
	}

	/* check if we are already signaled */

	for (i = 0; i < args.count; i++) {
		struct winesync_obj *obj = q->entries[i].obj;

		if (atomic_read(&q->signaled) != -1)
			break;

		spin_lock(&obj->lock);
		try_wake_any_obj(obj);
		spin_unlock(&obj->lock);
	}

	/* sleep */

	ret = winesync_schedule(q, args.timeout ? &timeout : NULL);

	/* and finally, unqueue */

	for (i = 0; i < args.count; i++) {
		struct winesync_q_entry *entry = &q->entries[i];
		struct winesync_obj *obj = entry->obj;

		spin_lock(&obj->lock);
		list_del(&entry->node);
		spin_unlock(&obj->lock);

		put_obj(obj);
	}

	signaled = atomic_read(&q->signaled);
	if (signaled != -1) {
		struct winesync_wait_args __user *user_args = argp;

		/* even if we caught a signal, we need to communicate success */
		ret = 0;

		if (put_user(signaled, &user_args->index))
			ret = -EFAULT;
	} else if (!ret) {
		ret = -ETIMEDOUT;
	}

	kfree(q);
	return ret;
}

static long winesync_char_ioctl(struct file *file, unsigned int cmd,
				unsigned long parm)
{
	struct winesync_device *dev = file->private_data;
	void __user *argp = (void __user *)parm;

	switch (cmd) {
	case WINESYNC_IOC_CREATE_SEM:
		return winesync_create_sem(dev, argp);
	case WINESYNC_IOC_DELETE:
		return winesync_delete(dev, argp);
	case WINESYNC_IOC_PUT_SEM:
		return winesync_put_sem(dev, argp);
	case WINESYNC_IOC_WAIT_ANY:
		return winesync_wait_any(dev, argp);
	default:
		return -ENOSYS;
	}
}

static const struct file_operations winesync_fops = {
	.owner		= THIS_MODULE,
	.open		= winesync_char_open,
	.release	= winesync_char_release,
	.unlocked_ioctl	= winesync_char_ioctl,
	.compat_ioctl	= winesync_char_ioctl,
	.llseek		= no_llseek,
};

static struct miscdevice winesync_misc = {
	.minor		= WINESYNC_MINOR,
	.name		= WINESYNC_NAME,
	.fops		= &winesync_fops,
};

static int __init winesync_init(void)
{
	return misc_register(&winesync_misc);
}

static void __exit winesync_exit(void)
{
	misc_deregister(&winesync_misc);
}

module_init(winesync_init);
module_exit(winesync_exit);

MODULE_AUTHOR("Zebediah Figura");
MODULE_DESCRIPTION("Kernel driver for Wine synchronization primitives");
MODULE_LICENSE("GPL");
MODULE_ALIAS("devname:" WINESYNC_NAME);
MODULE_ALIAS_MISCDEV(WINESYNC_MINOR);
