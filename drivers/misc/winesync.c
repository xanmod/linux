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

	enum winesync_type type;

	/* The following fields are protected by the object lock. */
	union {
		struct {
			__u32 count;
			__u32 max;
		} sem;
	} u;
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

	spin_unlock(&sem->lock);

	put_obj(sem);

	if (!ret && put_user(prev_count, &user_args->count))
		ret = -EFAULT;

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
