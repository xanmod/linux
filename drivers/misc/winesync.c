// SPDX-License-Identifier: GPL-2.0-only
/*
 * winesync.c - Kernel driver for Wine synchronization primitives
 *
 * Copyright (C) 2021 Zebediah Figura
 */

#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <uapi/linux/winesync.h>

#define WINESYNC_NAME	"winesync"

enum winesync_type {
	WINESYNC_TYPE_SEM,
	WINESYNC_TYPE_MUTEX,
};

struct winesync_obj {
	struct kref refcount;
	spinlock_t lock;

	/*
	 * any_waiters is protected by the object lock, but all_waiters is
	 * protected by the device wait_all_lock.
	 */
	struct list_head any_waiters;
	struct list_head all_waiters;

	/*
	 * Hint describing how many tasks are queued on this object in a
	 * wait-all operation.
	 *
	 * Any time we do a wake, we may need to wake "all" waiters as well as
	 * "any" waiters. In order to atomically wake "all" waiters, we must
	 * lock all of the objects, and that means grabbing the wait_all_lock
	 * below (and, due to lock ordering rules, before locking this object).
	 * However, wait-all is a rare operation, and grabbing the wait-all
	 * lock for every wake would create unnecessary contention. Therefore we
	 * first check whether all_hint is one, and, if it is, we skip trying
	 * to wake "all" waiters.
	 *
	 * This "refcount" isn't protected by any lock. It might change during
	 * the course of a wake, but there's no meaningful race there; it's only
	 * a hint.
	 *
	 * Use refcount_t rather than atomic_t to take advantage of saturation.
	 * This does mean that the "no waiters" case is signified by all_hint
	 * being one, rather than zero (otherwise we would get spurious
	 * warnings).
	 */
	refcount_t all_hint;

	enum winesync_type type;

	/* The following fields are protected by the object lock. */
	union {
		struct {
			__u32 count;
			__u32 max;
			__u32 flags;
		} sem;
		struct {
			__u32 count;
			__u32 owner;
			bool ownerdead;
		} mutex;
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

	bool all;
	bool ownerdead;
	__u32 count;
	struct winesync_q_entry entries[];
};

struct winesync_device {
	/*
	 * Wait-all operations must atomically grab all objects, and be totally
	 * ordered with respect to each other and wait-any operations. If one
	 * thread is trying to acquire several objects, another thread cannot
	 * touch the object at the same time.
	 *
	 * We achieve this by grabbing multiple object locks at the same time.
	 * However, this creates a lock ordering problem. To solve that problem,
	 * wait_all_lock is taken first whenever multiple objects must be locked
	 * at the same time.
	 */
	spinlock_t wait_all_lock;
	struct mutex table_lock;
	struct idr objects;
};

static struct winesync_obj *get_obj(struct winesync_device *dev, int id)
{
	struct winesync_obj *obj;

	rcu_read_lock();
	obj = idr_find(&dev->objects, id);
	if (obj && !kref_get_unless_zero(&obj->refcount))
		obj = NULL;
	rcu_read_unlock();

	return obj;
}

static void destroy_obj(struct kref *ref)
{
	struct winesync_obj *obj;

	obj = container_of(ref, struct winesync_obj, refcount);
	kfree(obj);
}

static void put_obj(struct winesync_obj *obj)
{
	kref_put(&obj->refcount, destroy_obj);
}

static int winesync_char_open(struct inode *inode, struct file *file)
{
	struct winesync_device *dev;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	idr_init(&dev->objects);
	spin_lock_init(&dev->wait_all_lock);
	mutex_init(&dev->table_lock);

	file->private_data = dev;
	return nonseekable_open(inode, file);
}

static int winesync_char_release(struct inode *inode, struct file *file)
{
	struct winesync_device *dev = file->private_data;
	struct winesync_obj *obj;
	int id;

	mutex_lock(&dev->table_lock);
	idr_for_each_entry(&dev->objects, obj, id) {
		idr_remove(&dev->objects, id);
		synchronize_rcu();
		put_obj(obj);
	}
	mutex_unlock(&dev->table_lock);

	kfree(dev);

	return 0;
}

static void winesync_init_obj(struct winesync_obj *obj)
{
	kref_init(&obj->refcount);
	refcount_set(&obj->all_hint, 1);
	spin_lock_init(&obj->lock);
	INIT_LIST_HEAD(&obj->any_waiters);
	INIT_LIST_HEAD(&obj->all_waiters);
}

static bool is_signaled(struct winesync_obj *obj, __u32 owner)
{
	lockdep_assert_held(&obj->lock);

	switch (obj->type) {
	case WINESYNC_TYPE_SEM:
		return !!obj->u.sem.count;
	case WINESYNC_TYPE_MUTEX:
		if (obj->u.mutex.owner && obj->u.mutex.owner != owner)
			return false;
		return obj->u.mutex.count < UINT_MAX;
	}

	WARN(1, "bad object type %#x\n", obj->type);
	return false;
}

/*
 * "locked_obj" is an optional pointer to an object which is already locked and
 * should not be locked again. This is necessary so that changing an object's
 * state and waking it can be a single atomic operation.
 */
static void try_wake_all(struct winesync_device *dev, struct winesync_q *q,
			 struct winesync_obj *locked_obj)
{
	__u32 count = q->count;
	bool can_wake = true;
	__u32 i;

	lockdep_assert_held(&dev->wait_all_lock);
	if (locked_obj)
		lockdep_assert_held(&locked_obj->lock);

	for (i = 0; i < count; i++) {
		if (q->entries[i].obj != locked_obj)
			spin_lock(&q->entries[i].obj->lock);
	}

	for (i = 0; i < count; i++) {
		if (!is_signaled(q->entries[i].obj, q->owner)) {
			can_wake = false;
			break;
		}
	}

	if (can_wake && atomic_cmpxchg(&q->signaled, -1, 0) == -1) {
		for (i = 0; i < count; i++) {
			struct winesync_obj *obj = q->entries[i].obj;

			switch (obj->type) {
			case WINESYNC_TYPE_SEM:
				if (obj->u.sem.flags & WINESYNC_SEM_GETONWAIT)
					obj->u.sem.count--;
				break;
			case WINESYNC_TYPE_MUTEX:
				if (obj->u.mutex.ownerdead)
					q->ownerdead = true;
				obj->u.mutex.ownerdead = false;
				obj->u.mutex.count++;
				obj->u.mutex.owner = q->owner;
				break;
			}
		}
		wake_up_process(q->task);
	}

	for (i = 0; i < count; i++) {
		if (q->entries[i].obj != locked_obj)
			spin_unlock(&q->entries[i].obj->lock);
	}
}

static void try_wake_all_obj(struct winesync_device *dev,
			     struct winesync_obj *obj)
{
	struct winesync_q_entry *entry;

	lockdep_assert_held(&dev->wait_all_lock);
	lockdep_assert_held(&obj->lock);

	list_for_each_entry(entry, &obj->all_waiters, node)
		try_wake_all(dev, entry->q, obj);
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
			if (sem->u.sem.flags & WINESYNC_SEM_GETONWAIT)
				sem->u.sem.count--;
			wake_up_process(q->task);
		}
	}
}

static void try_wake_any_mutex(struct winesync_obj *mutex)
{
	struct winesync_q_entry *entry;

	lockdep_assert_held(&mutex->lock);

	list_for_each_entry(entry, &mutex->any_waiters, node) {
		struct winesync_q *q = entry->q;

		if (mutex->u.mutex.count == UINT_MAX)
			break;
		if (mutex->u.mutex.owner && mutex->u.mutex.owner != q->owner)
			continue;

		if (atomic_cmpxchg(&q->signaled, -1, entry->index) == -1) {
			if (mutex->u.mutex.ownerdead)
				q->ownerdead = true;
			mutex->u.mutex.ownerdead = false;
			mutex->u.mutex.count++;
			mutex->u.mutex.owner = q->owner;
			wake_up_process(q->task);
		}
	}
}

static int winesync_create_sem(struct winesync_device *dev, void __user *argp)
{
	struct winesync_sem_args __user *user_args = argp;
	struct winesync_sem_args args;
	struct winesync_obj *sem;
	int ret;

	if (copy_from_user(&args, argp, sizeof(args)))
		return -EFAULT;

	if (args.count > args.max)
		return -EINVAL;

	if (args.flags & ~WINESYNC_SEM_GETONWAIT)
		return -EINVAL;

	sem = kzalloc(sizeof(*sem), GFP_KERNEL);
	if (!sem)
		return -ENOMEM;

	winesync_init_obj(sem);
	sem->type = WINESYNC_TYPE_SEM;
	sem->u.sem.count = args.count;
	sem->u.sem.max = args.max;
	sem->u.sem.flags = args.flags;

	mutex_lock(&dev->table_lock);
	ret = idr_alloc(&dev->objects, sem, 0, 0, GFP_KERNEL);
	mutex_unlock(&dev->table_lock);

	if (ret < 0) {
		kfree(sem);
		return ret;
	}

	return put_user(ret, &user_args->sem);
}

static int winesync_create_mutex(struct winesync_device *dev, void __user *argp)
{
	struct winesync_mutex_args __user *user_args = argp;
	struct winesync_mutex_args args;
	struct winesync_obj *mutex;
	int ret;

	if (copy_from_user(&args, argp, sizeof(args)))
		return -EFAULT;

	if (!args.owner != !args.count)
		return -EINVAL;

	mutex = kzalloc(sizeof(*mutex), GFP_KERNEL);
	if (!mutex)
		return -ENOMEM;

	winesync_init_obj(mutex);
	mutex->type = WINESYNC_TYPE_MUTEX;
	mutex->u.mutex.count = args.count;
	mutex->u.mutex.owner = args.owner;

	mutex_lock(&dev->table_lock);
	ret = idr_alloc(&dev->objects, mutex, 0, 0, GFP_KERNEL);
	mutex_unlock(&dev->table_lock);

	if (ret < 0) {
		kfree(mutex);
		return ret;
	}

	return put_user(ret, &user_args->mutex);
}

static int winesync_delete(struct winesync_device *dev, void __user *argp)
{
	struct winesync_obj *obj;
	__s32 id;

	if (get_user(id, (__s32 __user *)argp))
		return -EFAULT;

	mutex_lock(&dev->table_lock);
	obj = idr_remove(&dev->objects, id);
	mutex_unlock(&dev->table_lock);

	if (!obj)
		return -EINVAL;

	put_obj(obj);
	return 0;
}

static int winesync_get_sem(struct winesync_device *dev, void __user *argp)
{
	struct winesync_obj *sem;
	int ret = -EWOULDBLOCK;
	__s32 id;

	if (get_user(id, (__s32 __user *)argp))
		return -EFAULT;

	sem = get_obj(dev, id);
	if (!sem)
		return -EINVAL;
	if (sem->type != WINESYNC_TYPE_SEM) {
		put_obj(sem);
		return -EINVAL;
	}

	spin_lock(&sem->lock);

	if (sem->u.sem.count) {
		/*
		 * Decrement the semaphore's count, regardless of whether it
		 * has the WINESYNC_SEM_GETONWAIT flag set.
		 */
		sem->u.sem.count--;
		ret = 0;
	}

	spin_unlock(&sem->lock);

	put_obj(sem);

	return ret;
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

static int winesync_put_sem(struct winesync_device *dev, void __user *argp,
			    bool pulse)
{
	struct winesync_sem_args __user *user_args = argp;
	struct winesync_sem_args args;
	struct winesync_obj *sem;
	__u32 prev_count;
	int ret;

	if (copy_from_user(&args, argp, sizeof(args)))
		return -EFAULT;

	sem = get_obj(dev, args.sem);
	if (!sem)
		return -EINVAL;
	if (sem->type != WINESYNC_TYPE_SEM) {
		put_obj(sem);
		return -EINVAL;
	}

	if (refcount_read(&sem->all_hint) > 1) {
		spin_lock(&dev->wait_all_lock);
		spin_lock(&sem->lock);

		prev_count = sem->u.sem.count;
		ret = put_sem_state(sem, args.count);
		if (!ret) {
			try_wake_all_obj(dev, sem);
			try_wake_any_sem(sem);
		}

		if (pulse)
			sem->u.sem.count = 0;

		spin_unlock(&sem->lock);
		spin_unlock(&dev->wait_all_lock);
	} else {
		spin_lock(&sem->lock);

		prev_count = sem->u.sem.count;
		ret = put_sem_state(sem, args.count);
		if (!ret)
			try_wake_any_sem(sem);

		if (pulse)
			sem->u.sem.count = 0;

		spin_unlock(&sem->lock);
	}

	put_obj(sem);

	if (!ret && put_user(prev_count, &user_args->count))
		ret = -EFAULT;

	return ret;
}

/*
 * Actually change the mutex state, returning -EPERM if not the owner.
 */
static int put_mutex_state(struct winesync_obj *mutex,
			   const struct winesync_mutex_args *args)
{
	lockdep_assert_held(&mutex->lock);

	if (mutex->u.mutex.owner != args->owner)
		return -EPERM;

	if (!--mutex->u.mutex.count)
		mutex->u.mutex.owner = 0;
	return 0;
}

static int winesync_put_mutex(struct winesync_device *dev, void __user *argp)
{
	struct winesync_mutex_args __user *user_args = argp;
	struct winesync_mutex_args args;
	struct winesync_obj *mutex;
	__u32 prev_count;
	int ret;

	if (copy_from_user(&args, argp, sizeof(args)))
		return -EFAULT;
	if (!args.owner)
		return -EINVAL;

	mutex = get_obj(dev, args.mutex);
	if (!mutex)
		return -EINVAL;
	if (mutex->type != WINESYNC_TYPE_MUTEX) {
		put_obj(mutex);
		return -EINVAL;
	}

	if (refcount_read(&mutex->all_hint) > 1) {
		spin_lock(&dev->wait_all_lock);
		spin_lock(&mutex->lock);

		prev_count = mutex->u.mutex.count;
		ret = put_mutex_state(mutex, &args);
		if (!ret) {
			try_wake_all_obj(dev, mutex);
			try_wake_any_mutex(mutex);
		}

		spin_unlock(&mutex->lock);
		spin_unlock(&dev->wait_all_lock);
	} else {
		spin_lock(&mutex->lock);

		prev_count = mutex->u.mutex.count;
		ret = put_mutex_state(mutex, &args);
		if (!ret)
			try_wake_any_mutex(mutex);

		spin_unlock(&mutex->lock);
	}

	put_obj(mutex);

	if (!ret && put_user(prev_count, &user_args->count))
		ret = -EFAULT;

	return ret;
}

static int winesync_read_sem(struct winesync_device *dev, void __user *argp)
{
	struct winesync_sem_args __user *user_args = argp;
	struct winesync_sem_args args;
	struct winesync_obj *sem;
	__s32 id;

	if (get_user(id, &user_args->sem))
		return -EFAULT;

	sem = get_obj(dev, id);
	if (!sem)
		return -EINVAL;
	if (sem->type != WINESYNC_TYPE_SEM) {
		put_obj(sem);
		return -EINVAL;
	}

	args.sem = id;
	spin_lock(&sem->lock);
	args.count = sem->u.sem.count;
	args.max = sem->u.sem.max;
	args.flags = sem->u.sem.flags;
	spin_unlock(&sem->lock);

	put_obj(sem);

	if (copy_to_user(user_args, &args, sizeof(args)))
		return -EFAULT;
	return 0;
}

static int winesync_read_mutex(struct winesync_device *dev, void __user *argp)
{
	struct winesync_mutex_args __user *user_args = argp;
	struct winesync_mutex_args args;
	struct winesync_obj *mutex;
	__s32 id;
	int ret;

	if (get_user(id, &user_args->mutex))
		return -EFAULT;

	mutex = get_obj(dev, id);
	if (!mutex)
		return -EINVAL;
	if (mutex->type != WINESYNC_TYPE_MUTEX) {
		put_obj(mutex);
		return -EINVAL;
	}

	args.mutex = id;
	spin_lock(&mutex->lock);
	args.count = mutex->u.mutex.count;
	args.owner = mutex->u.mutex.owner;
	ret = mutex->u.mutex.ownerdead ? -EOWNERDEAD : 0;
	spin_unlock(&mutex->lock);

	put_obj(mutex);

	if (copy_to_user(user_args, &args, sizeof(args)))
		return -EFAULT;
	return ret;
}

/*
 * Actually change the mutex state to mark its owner as dead.
 */
static void put_mutex_ownerdead_state(struct winesync_obj *mutex)
{
	lockdep_assert_held(&mutex->lock);

	mutex->u.mutex.ownerdead = true;
	mutex->u.mutex.owner = 0;
	mutex->u.mutex.count = 0;
}

static int winesync_kill_owner(struct winesync_device *dev, void __user *argp)
{
	struct winesync_obj *obj;
	__u32 owner;
	int id;

	if (get_user(owner, (__u32 __user *)argp))
		return -EFAULT;
	if (!owner)
		return -EINVAL;

	rcu_read_lock();

	idr_for_each_entry(&dev->objects, obj, id) {
		if (!kref_get_unless_zero(&obj->refcount))
			continue;

		if (obj->type != WINESYNC_TYPE_MUTEX) {
			put_obj(obj);
			continue;
		}

		if (refcount_read(&obj->all_hint) > 1) {
			spin_lock(&dev->wait_all_lock);
			spin_lock(&obj->lock);

			if (obj->u.mutex.owner == owner) {
				put_mutex_ownerdead_state(obj);
				try_wake_all_obj(dev, obj);
				try_wake_any_mutex(obj);
			}

			spin_unlock(&obj->lock);
			spin_unlock(&dev->wait_all_lock);
		} else {
			spin_lock(&obj->lock);

			if (obj->u.mutex.owner == owner) {
				put_mutex_ownerdead_state(obj);
				try_wake_any_mutex(obj);
			}

			spin_unlock(&obj->lock);
		}

		put_obj(obj);
	}

	rcu_read_unlock();

	return 0;
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
 * Allocate and initialize most of the winesync_q structure, but do not queue us
 * yet. Also, calculate the relative timeout in jiffies.
 */
static int setup_wait(struct winesync_device *dev,
		      const struct winesync_wait_args *args, bool all,
		      ktime_t *ret_timeout, struct winesync_q **ret_q)
{
	const __u32 count = args->count;
	struct winesync_q *q;
	ktime_t timeout = 0;
	__s32 *ids;
	__u32 i, j;

	if (args->timeout) {
		struct timespec64 to;

		if (get_timespec64(&to, u64_to_user_ptr(args->timeout)))
			return -EFAULT;
		if (!timespec64_valid(&to))
			return -EINVAL;

		timeout = timespec64_to_ns(&to);
	}

	ids = kmalloc_array(args->count, sizeof(*ids), GFP_KERNEL);
	if (!ids)
		return -ENOMEM;
	if (copy_from_user(ids, u64_to_user_ptr(args->objs),
			   array_size(args->count, sizeof(*ids)))) {
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
	q->all = all;
	q->ownerdead = false;
	q->count = count;

	for (i = 0; i < count; i++) {
		struct winesync_q_entry *entry = &q->entries[i];
		struct winesync_obj *obj = get_obj(dev, ids[i]);

		if (!obj)
			goto err;

		if (all) {
			/* Check that the objects are all distinct. */
			for (j = 0; j < i; j++) {
				if (obj == q->entries[j].obj) {
					put_obj(obj);
					goto err;
				}
			}
		}

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
	case WINESYNC_TYPE_MUTEX:
		try_wake_any_mutex(obj);
		break;
	}
}

static int winesync_wait_any(struct winesync_device *dev, void __user *argp)
{
	struct winesync_wait_args args;
	struct winesync_q *q;
	ktime_t timeout;
	__u32 i;
	int ret;

	if (copy_from_user(&args, argp, sizeof(args)))
		return -EFAULT;
	if (!args.owner)
		return -EINVAL;

	ret = setup_wait(dev, &args, false, &timeout, &q);
	if (ret < 0)
		return ret;

	/* queue ourselves */

	for (i = 0; i < args.count; i++) {
		struct winesync_q_entry *entry = &q->entries[i];
		struct winesync_obj *obj = q->entries[i].obj;

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
		struct winesync_obj *obj = q->entries[i].obj;

		spin_lock(&obj->lock);
		list_del(&q->entries[i].node);
		spin_unlock(&obj->lock);

		put_obj(obj);
	}

	if (atomic_read(&q->signaled) != -1) {
		struct winesync_wait_args __user *user_args = argp;

		/* even if we caught a signal, we need to communicate success */
		ret = q->ownerdead ? -EOWNERDEAD : 0;

		if (put_user(atomic_read(&q->signaled), &user_args->index))
			ret = -EFAULT;
	} else if (!ret) {
		ret = -ETIMEDOUT;
	}

	kfree(q);
	return ret;
}

static int winesync_wait_all(struct winesync_device *dev, void __user *argp)
{
	struct winesync_wait_args args;
	struct winesync_q *q;
	ktime_t timeout;
	__u32 i;
	int ret;

	if (copy_from_user(&args, argp, sizeof(args)))
		return -EFAULT;
	if (!args.owner)
		return -EINVAL;

	ret = setup_wait(dev, &args, true, &timeout, &q);
	if (ret < 0)
		return ret;

	/* queue ourselves */

	spin_lock(&dev->wait_all_lock);

	for (i = 0; i < args.count; i++) {
		struct winesync_q_entry *entry = &q->entries[i];
		struct winesync_obj *obj = q->entries[i].obj;

		refcount_inc(&obj->all_hint);

		/*
		 * obj->all_waiters is protected by dev->wait_all_lock rather
		 * than obj->lock, so there is no need to acquire it here.
		 */
		list_add_tail(&entry->node, &obj->all_waiters);
	}

	/* check if we are already signaled */

	try_wake_all(dev, q, NULL);

	spin_unlock(&dev->wait_all_lock);

	/* sleep */

	ret = winesync_schedule(q, args.timeout ? &timeout : NULL);

	/* and finally, unqueue */

	spin_lock(&dev->wait_all_lock);

	for (i = 0; i < args.count; i++) {
		struct winesync_q_entry *entry = &q->entries[i];
		struct winesync_obj *obj = q->entries[i].obj;

		/*
		 * obj->all_waiters is protected by dev->wait_all_lock rather
		 * than obj->lock, so there is no need to acquire it here.
		 */
		list_del(&entry->node);

		refcount_dec(&obj->all_hint);

		put_obj(obj);
	}

	spin_unlock(&dev->wait_all_lock);

	if (atomic_read(&q->signaled) != -1) {
		/* even if we caught a signal, we need to communicate success */
		ret = q->ownerdead ? -EOWNERDEAD : 0;
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
	case WINESYNC_IOC_CREATE_MUTEX:
		return winesync_create_mutex(dev, argp);
	case WINESYNC_IOC_DELETE:
		return winesync_delete(dev, argp);
	case WINESYNC_IOC_GET_SEM:
		return winesync_get_sem(dev, argp);
	case WINESYNC_IOC_PUT_SEM:
		return winesync_put_sem(dev, argp, false);
	case WINESYNC_IOC_PULSE_SEM:
		return winesync_put_sem(dev, argp, true);
	case WINESYNC_IOC_PUT_MUTEX:
		return winesync_put_mutex(dev, argp);
	case WINESYNC_IOC_READ_SEM:
		return winesync_read_sem(dev, argp);
	case WINESYNC_IOC_READ_MUTEX:
		return winesync_read_mutex(dev, argp);
	case WINESYNC_IOC_KILL_OWNER:
		return winesync_kill_owner(dev, argp);
	case WINESYNC_IOC_WAIT_ANY:
		return winesync_wait_any(dev, argp);
	case WINESYNC_IOC_WAIT_ALL:
		return winesync_wait_all(dev, argp);
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
