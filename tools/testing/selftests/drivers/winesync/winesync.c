// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Various unit tests for the "winesync" synchronization primitive driver.
 *
 * Copyright (C) 2021 Zebediah Figura
 */

#define _GNU_SOURCE
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <linux/winesync.h>
#include "../../kselftest_harness.h"

static int read_sem_state(int fd, __u32 sem, __u32 *count, __u32 *max)
{
	struct winesync_sem_args args;
	int ret;

	args.sem = sem;
	args.count = 0xdeadbeef;
	args.max = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_READ_SEM, &args);
	*count = args.count;
	*max = args.max;
	return ret;
}

#define check_sem_state(fd, sem, count, max) \
	({ \
		__u32 __count, __max; \
		int ret = read_sem_state((fd), (sem), &__count, &__max); \
		EXPECT_EQ(0, ret); \
		EXPECT_EQ((count), __count); \
		EXPECT_EQ((max), __max); \
	})

static int put_sem(int fd, __u32 sem, __u32 *count)
{
	struct winesync_sem_args args;
	int ret;

	args.sem = sem;
	args.count = *count;
	ret = ioctl(fd, WINESYNC_IOC_PUT_SEM, &args);
	*count = args.count;
	return ret;
}

static int read_mutex_state(int fd, __u32 mutex, __u32 *count, __u32 *owner)
{
	struct winesync_mutex_args args;
	int ret;

	args.mutex = mutex;
	args.count = 0xdeadbeef;
	args.owner = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_READ_MUTEX, &args);
	*count = args.count;
	*owner = args.owner;
	return ret;
}

#define check_mutex_state(fd, mutex, count, owner) \
	({ \
		__u32 __count, __owner; \
		int ret = read_mutex_state((fd), (mutex), &__count, &__owner); \
		EXPECT_EQ(0, ret); \
		EXPECT_EQ((count), __count); \
		EXPECT_EQ((owner), __owner); \
	})

static int put_mutex(int fd, __u32 mutex, __u32 owner, __u32 *count)
{
	struct winesync_mutex_args args;
	int ret;

	args.mutex = mutex;
	args.owner = owner;
	args.count = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_PUT_MUTEX, &args);
	*count = args.count;
	return ret;
}

static int read_event_state(int fd, __u32 event, __u32 *signaled, __u32 *manual)
{
	struct winesync_event_args args;
	int ret;

	args.event = event;
	args.signaled = 0xdeadbeef;
	args.manual = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_READ_EVENT, &args);
	*signaled = args.signaled;
	*manual = args.manual;
	return ret;
}

#define check_event_state(fd, event, signaled, manual) \
	({ \
		__u32 __signaled, __manual; \
		int ret = read_event_state((fd), (event), \
					   &__signaled, &__manual); \
		EXPECT_EQ(0, ret); \
		EXPECT_EQ((signaled), __signaled); \
		EXPECT_EQ((manual), __manual); \
	})

static int wait_objs(int fd, unsigned long request, __u32 count,
		     const __u32 *objs, __u32 owner, __u32 alert, __u32 *index)
{
	struct winesync_wait_args args = {0};
	struct timespec timeout;
	int ret;

	clock_gettime(CLOCK_MONOTONIC, &timeout);

	args.timeout = (uintptr_t)&timeout;
	args.count = count;
	args.objs = (uintptr_t)objs;
	args.owner = owner;
	args.index = 0xdeadbeef;
	args.alert = alert;
	ret = ioctl(fd, request, &args);
	*index = args.index;
	return ret;
}

static int wait_any(int fd, __u32 count, const __u32 *objs,
		    __u32 owner, __u32 *index)
{
	return wait_objs(fd, WINESYNC_IOC_WAIT_ANY,
			 count, objs, owner, 0, index);
}

static int wait_all(int fd, __u32 count, const __u32 *objs,
		    __u32 owner, __u32 *index)
{
	return wait_objs(fd, WINESYNC_IOC_WAIT_ALL,
			 count, objs, owner, 0, index);
}

static int wait_any_alert(int fd, __u32 count, const __u32 *objs,
			  __u32 owner, __u32 alert, __u32 *index)
{
	return wait_objs(fd, WINESYNC_IOC_WAIT_ANY,
			 count, objs, owner, alert, index);
}

static int wait_all_alert(int fd, __u32 count, const __u32 *objs,
			  __u32 owner, __u32 alert, __u32 *index)
{
	return wait_objs(fd, WINESYNC_IOC_WAIT_ALL,
			 count, objs, owner, alert, index);
}

TEST(semaphore_state)
{
	struct winesync_sem_args sem_args;
	struct timespec timeout;
	__u32 sem, count, index;
	int fd, ret;

	clock_gettime(CLOCK_MONOTONIC, &timeout);

	fd = open("/dev/winesync", O_CLOEXEC | O_RDONLY);
	ASSERT_LE(0, fd);

	sem_args.count = 3;
	sem_args.max = 2;
	sem_args.sem = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_SEM, &sem_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	sem_args.count = 2;
	sem_args.max = 2;
	sem_args.sem = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_SEM, &sem_args);
	EXPECT_EQ(0, ret);
	EXPECT_NE(0xdeadbeef, sem_args.sem);
	check_sem_state(fd, sem, 2, 2);

	count = 0;
	ret = put_sem(fd, sem, &count);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(2, count);
	check_sem_state(fd, sem, 2, 2);

	count = 1;
	ret = put_sem(fd, sem, &count);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EOVERFLOW, errno);
	check_sem_state(fd, sem, 2, 2);

	ret = wait_any(fd, 1, &sem, 123, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);
	check_sem_state(fd, sem, 1, 2);

	ret = wait_any(fd, 1, &sem, 123, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);
	check_sem_state(fd, sem, 0, 2);

	ret = wait_any(fd, 1, &sem, 123, &index);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(ETIMEDOUT, errno);

	count = 3;
	ret = put_sem(fd, sem, &count);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EOVERFLOW, errno);
	check_sem_state(fd, sem, 0, 2);

	count = 2;
	ret = put_sem(fd, sem, &count);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, count);
	check_sem_state(fd, sem, 2, 2);

	ret = wait_any(fd, 1, &sem, 123, &index);
	EXPECT_EQ(0, ret);
	ret = wait_any(fd, 1, &sem, 123, &index);
	EXPECT_EQ(0, ret);

	count = 1;
	ret = put_sem(fd, sem, &count);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, count);
	check_sem_state(fd, sem, 1, 2);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &sem);
	EXPECT_EQ(0, ret);

	close(fd);
}

TEST(mutex_state)
{
	struct winesync_mutex_args mutex_args;
	__u32 mutex, owner, count, index;
	struct timespec timeout;
	int fd, ret;

	clock_gettime(CLOCK_MONOTONIC, &timeout);

	fd = open("/dev/winesync", O_CLOEXEC | O_RDONLY);
	ASSERT_LE(0, fd);

	mutex_args.owner = 123;
	mutex_args.count = 0;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_MUTEX, &mutex_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	mutex_args.owner = 0;
	mutex_args.count = 2;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_MUTEX, &mutex_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	mutex_args.owner = 123;
	mutex_args.count = 2;
	mutex_args.mutex = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_MUTEX, &mutex_args);
	EXPECT_EQ(0, ret);
	EXPECT_NE(0xdeadbeef, mutex_args.mutex);
	mutex = mutex_args.mutex;
	check_mutex_state(fd, mutex, 2, 123);

	ret = put_mutex(fd, mutex, 0, &count);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	ret = put_mutex(fd, mutex, 456, &count);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EPERM, errno);
	check_mutex_state(fd, mutex, 2, 123);

	ret = put_mutex(fd, mutex, 123, &count);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(2, count);
	check_mutex_state(fd, mutex, 1, 123);

	ret = put_mutex(fd, mutex, 123, &count);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, count);
	check_mutex_state(fd, mutex, 0, 0);

	ret = put_mutex(fd, mutex, 123, &count);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EPERM, errno);

	ret = wait_any(fd, 1, &mutex, 456, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);
	check_mutex_state(fd, mutex, 1, 456);

	ret = wait_any(fd, 1, &mutex, 456, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);
	check_mutex_state(fd, mutex, 2, 456);

	ret = put_mutex(fd, mutex, 456, &count);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(2, count);
	check_mutex_state(fd, mutex, 1, 456);

	ret = wait_any(fd, 1, &mutex, 123, &index);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(ETIMEDOUT, errno);

	owner = 0;
	ret = ioctl(fd, WINESYNC_IOC_KILL_OWNER, &owner);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	owner = 123;
	ret = ioctl(fd, WINESYNC_IOC_KILL_OWNER, &owner);
	EXPECT_EQ(0, ret);
	check_mutex_state(fd, mutex, 1, 456);

	owner = 456;
	ret = ioctl(fd, WINESYNC_IOC_KILL_OWNER, &owner);
	EXPECT_EQ(0, ret);

	mutex_args.count = 0xdeadbeef;
	mutex_args.owner = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_READ_MUTEX, &mutex_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EOWNERDEAD, errno);
	EXPECT_EQ(0, mutex_args.count);
	EXPECT_EQ(0, mutex_args.owner);

	mutex_args.count = 0xdeadbeef;
	mutex_args.owner = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_READ_MUTEX, &mutex_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EOWNERDEAD, errno);
	EXPECT_EQ(0, mutex_args.count);
	EXPECT_EQ(0, mutex_args.owner);

	ret = wait_any(fd, 1, &mutex, 123, &index);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EOWNERDEAD, errno);
	EXPECT_EQ(0, index);
	check_mutex_state(fd, mutex, 1, 123);

	owner = 123;
	ret = ioctl(fd, WINESYNC_IOC_KILL_OWNER, &owner);
	EXPECT_EQ(0, ret);

	mutex_args.count = 0xdeadbeef;
	mutex_args.owner = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_READ_MUTEX, &mutex_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EOWNERDEAD, errno);
	EXPECT_EQ(0, mutex_args.count);
	EXPECT_EQ(0, mutex_args.owner);

	ret = wait_any(fd, 1, &mutex, 123, &index);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EOWNERDEAD, errno);
	EXPECT_EQ(0, index);
	check_mutex_state(fd, mutex, 1, 123);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &mutex);
	EXPECT_EQ(0, ret);

	mutex_args.owner = 0;
	mutex_args.count = 0;
	mutex_args.mutex = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_MUTEX, &mutex_args);
	EXPECT_EQ(0, ret);
	EXPECT_NE(0xdeadbeef, mutex_args.mutex);
	mutex = mutex_args.mutex;
	check_mutex_state(fd, mutex, 0, 0);

	ret = wait_any(fd, 1, &mutex, 123, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);
	check_mutex_state(fd, mutex, 1, 123);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &mutex_args.mutex);
	EXPECT_EQ(0, ret);

	close(fd);
}

TEST(manual_event_state)
{
	struct winesync_event_args event_args;
	__u32 index;
	int fd, ret;

	fd = open("/dev/winesync", O_CLOEXEC | O_RDONLY);
	ASSERT_LE(0, fd);

	event_args.manual = 1;
	event_args.signaled = 0;
	event_args.event = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_EVENT, &event_args);
	EXPECT_EQ(0, ret);
	EXPECT_NE(0xdeadbeef, event_args.event);
	check_event_state(fd, event_args.event, 0, 1);

	event_args.signaled = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_SET_EVENT, &event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, event_args.signaled);
	check_event_state(fd, event_args.event, 1, 1);

	ret = ioctl(fd, WINESYNC_IOC_SET_EVENT, &event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, event_args.signaled);
	check_event_state(fd, event_args.event, 1, 1);

	ret = wait_any(fd, 1, &event_args.event, 123, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);
	check_event_state(fd, event_args.event, 1, 1);

	event_args.signaled = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_RESET_EVENT, &event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, event_args.signaled);
	check_event_state(fd, event_args.event, 0, 1);

	ret = ioctl(fd, WINESYNC_IOC_RESET_EVENT, &event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, event_args.signaled);
	check_event_state(fd, event_args.event, 0, 1);

	ret = wait_any(fd, 1, &event_args.event, 123, &index);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(ETIMEDOUT, errno);

	ret = ioctl(fd, WINESYNC_IOC_SET_EVENT, &event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, event_args.signaled);

	ret = ioctl(fd, WINESYNC_IOC_PULSE_EVENT, &event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, event_args.signaled);
	check_event_state(fd, event_args.event, 0, 1);

	ret = ioctl(fd, WINESYNC_IOC_PULSE_EVENT, &event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, event_args.signaled);
	check_event_state(fd, event_args.event, 0, 1);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &event_args.event);
	EXPECT_EQ(0, ret);

	close(fd);
}

TEST(auto_event_state)
{
	struct winesync_event_args event_args;
	__u32 index;
	int fd, ret;

	fd = open("/dev/winesync", O_CLOEXEC | O_RDONLY);
	ASSERT_LE(0, fd);

	event_args.manual = 0;
	event_args.signaled = 1;
	event_args.event = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_EVENT, &event_args);
	EXPECT_EQ(0, ret);
	EXPECT_NE(0xdeadbeef, event_args.event);

	check_event_state(fd, event_args.event, 1, 0);

	event_args.signaled = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_SET_EVENT, &event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, event_args.signaled);
	check_event_state(fd, event_args.event, 1, 0);

	ret = wait_any(fd, 1, &event_args.event, 123, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);
	check_event_state(fd, event_args.event, 0, 0);

	event_args.signaled = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_RESET_EVENT, &event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, event_args.signaled);
	check_event_state(fd, event_args.event, 0, 0);

	ret = wait_any(fd, 1, &event_args.event, 123, &index);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(ETIMEDOUT, errno);

	ret = ioctl(fd, WINESYNC_IOC_SET_EVENT, &event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, event_args.signaled);

	ret = ioctl(fd, WINESYNC_IOC_PULSE_EVENT, &event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, event_args.signaled);
	check_event_state(fd, event_args.event, 0, 0);

	ret = ioctl(fd, WINESYNC_IOC_PULSE_EVENT, &event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, event_args.signaled);
	check_event_state(fd, event_args.event, 0, 0);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &event_args.event);
	EXPECT_EQ(0, ret);

	close(fd);
}

TEST(test_wait_any)
{
	struct winesync_mutex_args mutex_args = {0};
	struct winesync_wait_args wait_args = {0};
	struct winesync_sem_args sem_args = {0};
	__u32 objs[2], owner, index;
	struct timespec timeout;
	int fd, ret;

	clock_gettime(CLOCK_MONOTONIC, &timeout);

	fd = open("/dev/winesync", O_CLOEXEC | O_RDONLY);
	ASSERT_LE(0, fd);

	sem_args.count = 2;
	sem_args.max = 3;
	sem_args.sem = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_SEM, &sem_args);
	EXPECT_EQ(0, ret);
	EXPECT_NE(0xdeadbeef, sem_args.sem);

	mutex_args.owner = 0;
	mutex_args.count = 0;
	mutex_args.mutex = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_MUTEX, &mutex_args);
	EXPECT_EQ(0, ret);
	EXPECT_NE(0xdeadbeef, mutex_args.mutex);

	objs[0] = sem_args.sem;
	objs[1] = mutex_args.mutex;

	ret = wait_any(fd, 2, objs, 123, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);
	check_sem_state(fd, sem_args.sem, 1, 3);
	check_mutex_state(fd, mutex_args.mutex, 0, 0);

	ret = wait_any(fd, 2, objs, 123, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);
	check_sem_state(fd, sem_args.sem, 0, 3);
	check_mutex_state(fd, mutex_args.mutex, 0, 0);

	ret = wait_any(fd, 2, objs, 123, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, index);
	check_sem_state(fd, sem_args.sem, 0, 3);
	check_mutex_state(fd, mutex_args.mutex, 1, 123);

	sem_args.count = 1;
	ret = ioctl(fd, WINESYNC_IOC_PUT_SEM, &sem_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, sem_args.count);

	ret = wait_any(fd, 2, objs, 123, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);
	check_sem_state(fd, sem_args.sem, 0, 3);
	check_mutex_state(fd, mutex_args.mutex, 1, 123);

	ret = wait_any(fd, 2, objs, 123, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, index);
	check_sem_state(fd, sem_args.sem, 0, 3);
	check_mutex_state(fd, mutex_args.mutex, 2, 123);

	ret = wait_any(fd, 2, objs, 456, &index);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(ETIMEDOUT, errno);

	owner = 123;
	ret = ioctl(fd, WINESYNC_IOC_KILL_OWNER, &owner);
	EXPECT_EQ(0, ret);

	ret = wait_any(fd, 2, objs, 456, &index);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EOWNERDEAD, errno);
	EXPECT_EQ(1, index);

	ret = wait_any(fd, 2, objs, 456, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, index);

	/* test waiting on the same object twice */
	sem_args.count = 2;
	ret = ioctl(fd, WINESYNC_IOC_PUT_SEM, &sem_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, sem_args.count);

	objs[0] = objs[1] = sem_args.sem;
	ret = wait_any(fd, 2, objs, 456, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, wait_args.index);
	check_sem_state(fd, sem_args.sem, 1, 3);

	ret = wait_any(fd, 0, NULL, 456, &index);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(ETIMEDOUT, errno);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &sem_args.sem);
	EXPECT_EQ(0, ret);
	ret = ioctl(fd, WINESYNC_IOC_DELETE, &mutex_args.mutex);
	EXPECT_EQ(0, ret);

	close(fd);
}

TEST(test_wait_all)
{
	struct winesync_event_args event_args = {0};
	struct winesync_mutex_args mutex_args = {0};
	struct winesync_sem_args sem_args = {0};
	__u32 objs[2], owner, index;
	int fd, ret;

	fd = open("/dev/winesync", O_CLOEXEC | O_RDONLY);
	ASSERT_LE(0, fd);

	sem_args.count = 2;
	sem_args.max = 3;
	sem_args.sem = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_SEM, &sem_args);
	EXPECT_EQ(0, ret);
	EXPECT_NE(0xdeadbeef, sem_args.sem);

	mutex_args.owner = 0;
	mutex_args.count = 0;
	mutex_args.mutex = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_MUTEX, &mutex_args);
	EXPECT_EQ(0, ret);
	EXPECT_NE(0xdeadbeef, mutex_args.mutex);

	event_args.manual = true;
	event_args.signaled = true;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_EVENT, &event_args);
	EXPECT_EQ(0, ret);

	objs[0] = sem_args.sem;
	objs[1] = mutex_args.mutex;

	ret = wait_all(fd, 2, objs, 123, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);
	check_sem_state(fd, sem_args.sem, 1, 3);
	check_mutex_state(fd, mutex_args.mutex, 1, 123);

	ret = wait_all(fd, 2, objs, 456, &index);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(ETIMEDOUT, errno);
	check_sem_state(fd, sem_args.sem, 1, 3);
	check_mutex_state(fd, mutex_args.mutex, 1, 123);

	ret = wait_all(fd, 2, objs, 123, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);
	check_sem_state(fd, sem_args.sem, 0, 3);
	check_mutex_state(fd, mutex_args.mutex, 2, 123);

	ret = wait_all(fd, 2, objs, 123, &index);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(ETIMEDOUT, errno);
	check_sem_state(fd, sem_args.sem, 0, 3);
	check_mutex_state(fd, mutex_args.mutex, 2, 123);

	sem_args.count = 3;
	ret = ioctl(fd, WINESYNC_IOC_PUT_SEM, &sem_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, sem_args.count);

	ret = wait_all(fd, 2, objs, 123, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);
	check_sem_state(fd, sem_args.sem, 2, 3);
	check_mutex_state(fd, mutex_args.mutex, 3, 123);

	owner = 123;
	ret = ioctl(fd, WINESYNC_IOC_KILL_OWNER, &owner);
	EXPECT_EQ(0, ret);

	ret = wait_all(fd, 2, objs, 123, &index);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EOWNERDEAD, errno);
	check_sem_state(fd, sem_args.sem, 1, 3);
	check_mutex_state(fd, mutex_args.mutex, 1, 123);

	objs[0] = sem_args.sem;
	objs[1] = event_args.event;
	ret = wait_all(fd, 2, objs, 123, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);
	check_sem_state(fd, sem_args.sem, 0, 3);
	check_event_state(fd, event_args.event, 1, 1);

	/* test waiting on the same object twice */
	objs[0] = objs[1] = sem_args.sem;
	ret = wait_all(fd, 2, objs, 123, &index);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &sem_args.sem);
	EXPECT_EQ(0, ret);
	ret = ioctl(fd, WINESYNC_IOC_DELETE, &mutex_args.mutex);
	EXPECT_EQ(0, ret);
	ret = ioctl(fd, WINESYNC_IOC_DELETE, &event_args.event);
	EXPECT_EQ(0, ret);

	close(fd);
}

TEST(invalid_objects)
{
	struct winesync_event_args event_args = {0};
	struct winesync_mutex_args mutex_args = {0};
	struct winesync_wait_args wait_args = {0};
	struct winesync_sem_args sem_args = {0};
	__u32 objs[2] = {0};
	int fd, ret;

	fd = open("/dev/winesync", O_CLOEXEC | O_RDONLY);
	ASSERT_LE(0, fd);

	ret = ioctl(fd, WINESYNC_IOC_PUT_SEM, &sem_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	ret = ioctl(fd, WINESYNC_IOC_READ_SEM, &sem_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	ret = ioctl(fd, WINESYNC_IOC_PUT_MUTEX, &mutex_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	ret = ioctl(fd, WINESYNC_IOC_READ_MUTEX, &mutex_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	ret = ioctl(fd, WINESYNC_IOC_SET_EVENT, &event_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	ret = ioctl(fd, WINESYNC_IOC_RESET_EVENT, &event_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	ret = ioctl(fd, WINESYNC_IOC_PULSE_EVENT, &event_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	ret = ioctl(fd, WINESYNC_IOC_READ_EVENT, &event_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	wait_args.objs = (uintptr_t)objs;
	wait_args.count = 1;
	ret = ioctl(fd, WINESYNC_IOC_WAIT_ANY, &wait_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);
	ret = ioctl(fd, WINESYNC_IOC_WAIT_ALL, &wait_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &objs[0]);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	sem_args.max = 1;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_SEM, &sem_args);
	EXPECT_EQ(0, ret);

	mutex_args.mutex = sem_args.sem;
	ret = ioctl(fd, WINESYNC_IOC_PUT_MUTEX, &mutex_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	ret = ioctl(fd, WINESYNC_IOC_READ_MUTEX, &mutex_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	event_args.event = sem_args.sem;
	ret = ioctl(fd, WINESYNC_IOC_SET_EVENT, &event_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	ret = ioctl(fd, WINESYNC_IOC_RESET_EVENT, &event_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	ret = ioctl(fd, WINESYNC_IOC_PULSE_EVENT, &event_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	ret = ioctl(fd, WINESYNC_IOC_READ_EVENT, &event_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	objs[0] = sem_args.sem;
	objs[1] = sem_args.sem + 1;
	wait_args.count = 2;
	ret = ioctl(fd, WINESYNC_IOC_WAIT_ANY, &wait_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);
	ret = ioctl(fd, WINESYNC_IOC_WAIT_ALL, &wait_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	objs[0] = sem_args.sem + 1;
	objs[1] = sem_args.sem;
	ret = ioctl(fd, WINESYNC_IOC_WAIT_ANY, &wait_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);
	ret = ioctl(fd, WINESYNC_IOC_WAIT_ALL, &wait_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &sem_args.sem);
	EXPECT_EQ(0, ret);

	ret = ioctl(fd, WINESYNC_IOC_CREATE_MUTEX, &mutex_args);
	EXPECT_EQ(0, ret);

	sem_args.sem = mutex_args.mutex;
	ret = ioctl(fd, WINESYNC_IOC_PUT_SEM, &sem_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	ret = ioctl(fd, WINESYNC_IOC_READ_SEM, &sem_args);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(EINVAL, errno);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &mutex_args.mutex);
	EXPECT_EQ(0, ret);

	close(fd);
}

struct wake_args
{
	int fd;
	__u32 obj;
};

struct wait_args
{
	int fd;
	unsigned long request;
	struct winesync_wait_args *args;
	int ret;
	int err;
};

static void *wait_thread(void *arg)
{
	struct wait_args *args = arg;

	args->ret = ioctl(args->fd, args->request, args->args);
	args->err = errno;
	return NULL;
}

static void get_abs_timeout(struct timespec *timeout, clockid_t clock,
			    unsigned int ms)
{
	clock_gettime(clock, timeout);
	timeout->tv_nsec += ms * 1000000;
	timeout->tv_sec += (timeout->tv_nsec / 1000000000);
	timeout->tv_nsec %= 1000000000;
}

static int wait_for_thread(pthread_t thread, unsigned int ms)
{
	struct timespec timeout;
	get_abs_timeout(&timeout, CLOCK_REALTIME, ms);
	return pthread_timedjoin_np(thread, NULL, &timeout);
}

TEST(wake_any)
{
	struct winesync_event_args event_args = {0};
	struct winesync_mutex_args mutex_args = {0};
	struct winesync_wait_args wait_args = {0};
	struct winesync_sem_args sem_args = {0};
	struct wait_args thread_args;
	__u32 objs[2], count, index;
	struct timespec timeout;
	pthread_t thread;
	int fd, ret;

	fd = open("/dev/winesync", O_CLOEXEC | O_RDONLY);
	ASSERT_LE(0, fd);

	sem_args.count = 0;
	sem_args.max = 3;
	sem_args.sem = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_SEM, &sem_args);
	EXPECT_EQ(0, ret);
	EXPECT_NE(0xdeadbeef, sem_args.sem);

	mutex_args.owner = 123;
	mutex_args.count = 1;
	mutex_args.mutex = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_MUTEX, &mutex_args);
	EXPECT_EQ(0, ret);
	EXPECT_NE(0xdeadbeef, mutex_args.mutex);

	objs[0] = sem_args.sem;
	objs[1] = mutex_args.mutex;

	/* test waking the semaphore */

	get_abs_timeout(&timeout, CLOCK_MONOTONIC, 1000);
	wait_args.timeout = (uintptr_t)&timeout;
	wait_args.objs = (uintptr_t)objs;
	wait_args.count = 2;
	wait_args.owner = 456;
	wait_args.index = 0xdeadbeef;
	thread_args.fd = fd;
	thread_args.args = &wait_args;
	thread_args.request = WINESYNC_IOC_WAIT_ANY;
	ret = pthread_create(&thread, NULL, wait_thread, &thread_args);
	EXPECT_EQ(0, ret);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(ETIMEDOUT, ret);

	sem_args.count = 1;
	ret = ioctl(fd, WINESYNC_IOC_PUT_SEM, &sem_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, sem_args.count);
	check_sem_state(fd, sem_args.sem, 0, 3);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, thread_args.ret);
	EXPECT_EQ(0, wait_args.index);

	/* test waking the mutex */

	/* first grab it again for owner 123 */
	ret = wait_any(fd, 1, &mutex_args.mutex, 123, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);

	get_abs_timeout(&timeout, CLOCK_MONOTONIC, 1000);
	wait_args.owner = 456;
	ret = pthread_create(&thread, NULL, wait_thread, &thread_args);
	EXPECT_EQ(0, ret);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(ETIMEDOUT, ret);

	ret = put_mutex(fd, mutex_args.mutex, 123, &count);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(2, count);

	ret = pthread_tryjoin_np(thread, NULL);
	EXPECT_EQ(EBUSY, ret);

	ret = put_mutex(fd, mutex_args.mutex, 123, &count);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, mutex_args.count);
	check_mutex_state(fd, mutex_args.mutex, 1, 456);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, thread_args.ret);
	EXPECT_EQ(1, wait_args.index);

	/* test waking events */

	event_args.manual = false;
	event_args.signaled = false;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_EVENT, &event_args);
	EXPECT_EQ(0, ret);

	objs[1] = event_args.event;
	get_abs_timeout(&timeout, CLOCK_MONOTONIC, 1000);
	ret = pthread_create(&thread, NULL, wait_thread, &thread_args);
	EXPECT_EQ(0, ret);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(ETIMEDOUT, ret);

	ret = ioctl(fd, WINESYNC_IOC_SET_EVENT, &event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, event_args.signaled);
	check_event_state(fd, event_args.event, 0, 0);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, thread_args.ret);
	EXPECT_EQ(1, wait_args.index);

	get_abs_timeout(&timeout, CLOCK_MONOTONIC, 1000);
	ret = pthread_create(&thread, NULL, wait_thread, &thread_args);
	EXPECT_EQ(0, ret);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(ETIMEDOUT, ret);

	ret = ioctl(fd, WINESYNC_IOC_PULSE_EVENT, &event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, event_args.signaled);
	check_event_state(fd, event_args.event, 0, 0);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, thread_args.ret);
	EXPECT_EQ(1, wait_args.index);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &event_args.event);
	EXPECT_EQ(0, ret);

	event_args.manual = true;
	event_args.signaled = false;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_EVENT, &event_args);
	EXPECT_EQ(0, ret);

	objs[1] = event_args.event;
	get_abs_timeout(&timeout, CLOCK_MONOTONIC, 1000);
	ret = pthread_create(&thread, NULL, wait_thread, &thread_args);
	EXPECT_EQ(0, ret);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(ETIMEDOUT, ret);

	ret = ioctl(fd, WINESYNC_IOC_SET_EVENT, &event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, event_args.signaled);
	check_event_state(fd, event_args.event, 1, 1);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, thread_args.ret);
	EXPECT_EQ(1, wait_args.index);

	ret = ioctl(fd, WINESYNC_IOC_RESET_EVENT, &event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, event_args.signaled);

	get_abs_timeout(&timeout, CLOCK_MONOTONIC, 1000);
	ret = pthread_create(&thread, NULL, wait_thread, &thread_args);
	EXPECT_EQ(0, ret);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(ETIMEDOUT, ret);

	ret = ioctl(fd, WINESYNC_IOC_PULSE_EVENT, &event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, event_args.signaled);
	check_event_state(fd, event_args.event, 0, 1);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, thread_args.ret);
	EXPECT_EQ(1, wait_args.index);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &event_args.event);
	EXPECT_EQ(0, ret);

	/* delete an object while it's being waited on */

	get_abs_timeout(&timeout, CLOCK_MONOTONIC, 200);
	wait_args.owner = 123;
	objs[1] = mutex_args.mutex;
	ret = pthread_create(&thread, NULL, wait_thread, &thread_args);
	EXPECT_EQ(0, ret);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(ETIMEDOUT, ret);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &sem_args.sem);
	EXPECT_EQ(0, ret);
	ret = ioctl(fd, WINESYNC_IOC_DELETE, &mutex_args.mutex);
	EXPECT_EQ(0, ret);

	ret = wait_for_thread(thread, 200);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(-1, thread_args.ret);
	EXPECT_EQ(ETIMEDOUT, thread_args.err);

	close(fd);
}

TEST(wake_all)
{
	struct winesync_event_args manual_event_args = {0};
	struct winesync_event_args auto_event_args = {0};
	struct winesync_mutex_args mutex_args = {0};
	struct winesync_wait_args wait_args = {0};
	struct winesync_sem_args sem_args = {0};
	struct wait_args thread_args;
	__u32 objs[4], count, index;
	struct timespec timeout;
	pthread_t thread;
	int fd, ret;

	fd = open("/dev/winesync", O_CLOEXEC | O_RDONLY);
	ASSERT_LE(0, fd);

	sem_args.count = 0;
	sem_args.max = 3;
	sem_args.sem = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_SEM, &sem_args);
	EXPECT_EQ(0, ret);
	EXPECT_NE(0xdeadbeef, sem_args.sem);

	mutex_args.owner = 123;
	mutex_args.count = 1;
	mutex_args.mutex = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_MUTEX, &mutex_args);
	EXPECT_EQ(0, ret);
	EXPECT_NE(0xdeadbeef, mutex_args.mutex);

	manual_event_args.manual = true;
	manual_event_args.signaled = true;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_EVENT, &manual_event_args);
	EXPECT_EQ(0, ret);

	auto_event_args.manual = false;
	auto_event_args.signaled = true;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_EVENT, &auto_event_args);
	EXPECT_EQ(0, ret);

	objs[0] = sem_args.sem;
	objs[1] = mutex_args.mutex;
	objs[2] = manual_event_args.event;
	objs[3] = auto_event_args.event;

	get_abs_timeout(&timeout, CLOCK_MONOTONIC, 1000);
	wait_args.timeout = (uintptr_t)&timeout;
	wait_args.objs = (uintptr_t)objs;
	wait_args.count = 4;
	wait_args.owner = 456;
	thread_args.fd = fd;
	thread_args.args = &wait_args;
	thread_args.request = WINESYNC_IOC_WAIT_ALL;
	ret = pthread_create(&thread, NULL, wait_thread, &thread_args);
	EXPECT_EQ(0, ret);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(ETIMEDOUT, ret);

	sem_args.count = 1;
	ret = ioctl(fd, WINESYNC_IOC_PUT_SEM, &sem_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, sem_args.count);

	ret = pthread_tryjoin_np(thread, NULL);
	EXPECT_EQ(EBUSY, ret);

	check_sem_state(fd, sem_args.sem, 1, 3);

	ret = wait_any(fd, 1, &sem_args.sem, 123, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);

	ret = put_mutex(fd, mutex_args.mutex, 123, &count);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, count);

	ret = pthread_tryjoin_np(thread, NULL);
	EXPECT_EQ(EBUSY, ret);

	check_mutex_state(fd, mutex_args.mutex, 0, 0);

	ret = ioctl(fd, WINESYNC_IOC_RESET_EVENT, &manual_event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, manual_event_args.signaled);

	sem_args.count = 2;
	ret = ioctl(fd, WINESYNC_IOC_PUT_SEM, &sem_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, sem_args.count);
	check_sem_state(fd, sem_args.sem, 2, 3);

	ret = ioctl(fd, WINESYNC_IOC_RESET_EVENT, &auto_event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, auto_event_args.signaled);

	ret = ioctl(fd, WINESYNC_IOC_SET_EVENT, &manual_event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, manual_event_args.signaled);

	ret = ioctl(fd, WINESYNC_IOC_SET_EVENT, &auto_event_args);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, auto_event_args.signaled);

	check_sem_state(fd, sem_args.sem, 1, 3);
	check_mutex_state(fd, mutex_args.mutex, 1, 456);
	check_event_state(fd, manual_event_args.event, 1, 1);
	check_event_state(fd, auto_event_args.event, 0, 0);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, thread_args.ret);

	/* delete an object while it's being waited on */

	get_abs_timeout(&timeout, CLOCK_MONOTONIC, 200);
	wait_args.owner = 123;
	ret = pthread_create(&thread, NULL, wait_thread, &thread_args);
	EXPECT_EQ(0, ret);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(ETIMEDOUT, ret);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &sem_args.sem);
	EXPECT_EQ(0, ret);
	ret = ioctl(fd, WINESYNC_IOC_DELETE, &mutex_args.mutex);
	EXPECT_EQ(0, ret);
	ret = ioctl(fd, WINESYNC_IOC_DELETE, &manual_event_args.event);
	EXPECT_EQ(0, ret);
	ret = ioctl(fd, WINESYNC_IOC_DELETE, &auto_event_args.event);
	EXPECT_EQ(0, ret);

	ret = wait_for_thread(thread, 200);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(-1, thread_args.ret);
	EXPECT_EQ(ETIMEDOUT, thread_args.err);

	close(fd);
}

TEST(alert_any)
{
	struct winesync_event_args event_args = {0};
	struct winesync_wait_args wait_args = {0};
	struct winesync_sem_args sem_args = {0};
	struct wait_args thread_args;
	struct timespec timeout;
	__u32 objs[2], index;
	pthread_t thread;
	int fd, ret;

	fd = open("/dev/winesync", O_CLOEXEC | O_RDONLY);
	ASSERT_LE(0, fd);

	sem_args.count = 0;
	sem_args.max = 2;
	sem_args.sem = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_SEM, &sem_args);
	EXPECT_EQ(0, ret);
	EXPECT_NE(0xdeadbeef, sem_args.sem);
	objs[0] = sem_args.sem;

	sem_args.count = 1;
	sem_args.max = 2;
	sem_args.sem = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_SEM, &sem_args);
	EXPECT_EQ(0, ret);
	EXPECT_NE(0xdeadbeef, sem_args.sem);
	objs[1] = sem_args.sem;

	event_args.manual = true;
	event_args.signaled = true;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_EVENT, &event_args);
	EXPECT_EQ(0, ret);

	ret = wait_any_alert(fd, 0, NULL, 123, event_args.event, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);

	ret = ioctl(fd, WINESYNC_IOC_RESET_EVENT, &event_args);
	EXPECT_EQ(0, ret);

	ret = wait_any_alert(fd, 0, NULL, 123, event_args.event, &index);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(ETIMEDOUT, errno);

	ret = ioctl(fd, WINESYNC_IOC_SET_EVENT, &event_args);
	EXPECT_EQ(0, ret);

	ret = wait_any_alert(fd, 2, objs, 123, event_args.event, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, index);

	ret = wait_any_alert(fd, 2, objs, 123, event_args.event, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(2, index);

	/* test wakeup via alert */

	ret = ioctl(fd, WINESYNC_IOC_RESET_EVENT, &event_args);
	EXPECT_EQ(0, ret);

	get_abs_timeout(&timeout, CLOCK_MONOTONIC, 1000);
	wait_args.timeout = (uintptr_t)&timeout;
	wait_args.objs = (uintptr_t)objs;
	wait_args.count = 2;
	wait_args.owner = 123;
	wait_args.index = 0xdeadbeef;
	wait_args.alert = event_args.event;
	thread_args.fd = fd;
	thread_args.args = &wait_args;
	thread_args.request = WINESYNC_IOC_WAIT_ANY;
	ret = pthread_create(&thread, NULL, wait_thread, &thread_args);
	EXPECT_EQ(0, ret);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(ETIMEDOUT, ret);

	ret = ioctl(fd, WINESYNC_IOC_SET_EVENT, &event_args);
	EXPECT_EQ(0, ret);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, thread_args.ret);
	EXPECT_EQ(2, wait_args.index);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &event_args.event);
	EXPECT_EQ(0, ret);

	/* test with an auto-reset event */

	event_args.manual = false;
	event_args.signaled = true;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_EVENT, &event_args);
	EXPECT_EQ(0, ret);

	sem_args.sem = objs[0];
	sem_args.count = 1;
	ret = ioctl(fd, WINESYNC_IOC_PUT_SEM, &sem_args);
	EXPECT_EQ(0, ret);

	ret = wait_any_alert(fd, 2, objs, 123, event_args.event, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);

	ret = wait_any_alert(fd, 2, objs, 123, event_args.event, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(2, index);

	ret = wait_any_alert(fd, 2, objs, 123, event_args.event, &index);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(ETIMEDOUT, errno);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &event_args.event);
	EXPECT_EQ(0, ret);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &objs[0]);
	EXPECT_EQ(0, ret);
	ret = ioctl(fd, WINESYNC_IOC_DELETE, &objs[1]);
	EXPECT_EQ(0, ret);

	close(fd);
}

TEST(alert_all)
{
	struct winesync_event_args event_args = {0};
	struct winesync_wait_args wait_args = {0};
	struct winesync_sem_args sem_args = {0};
	struct wait_args thread_args;
	struct timespec timeout;
	__u32 objs[2], index;
	pthread_t thread;
	int fd, ret;

	fd = open("/dev/winesync", O_CLOEXEC | O_RDONLY);
	ASSERT_LE(0, fd);

	sem_args.count = 2;
	sem_args.max = 2;
	sem_args.sem = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_SEM, &sem_args);
	EXPECT_EQ(0, ret);
	EXPECT_NE(0xdeadbeef, sem_args.sem);
	objs[0] = sem_args.sem;

	sem_args.count = 1;
	sem_args.max = 2;
	sem_args.sem = 0xdeadbeef;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_SEM, &sem_args);
	EXPECT_EQ(0, ret);
	EXPECT_NE(0xdeadbeef, sem_args.sem);
	objs[1] = sem_args.sem;

	event_args.manual = true;
	event_args.signaled = true;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_EVENT, &event_args);
	EXPECT_EQ(0, ret);

	ret = wait_all_alert(fd, 2, objs, 123, event_args.event, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);

	ret = wait_all_alert(fd, 2, objs, 123, event_args.event, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(2, index);

	/* test wakeup via alert */

	ret = ioctl(fd, WINESYNC_IOC_RESET_EVENT, &event_args);
	EXPECT_EQ(0, ret);

	get_abs_timeout(&timeout, CLOCK_MONOTONIC, 1000);
	wait_args.timeout = (uintptr_t)&timeout;
	wait_args.objs = (uintptr_t)objs;
	wait_args.count = 2;
	wait_args.owner = 123;
	wait_args.index = 0xdeadbeef;
	wait_args.alert = event_args.event;
	thread_args.fd = fd;
	thread_args.args = &wait_args;
	thread_args.request = WINESYNC_IOC_WAIT_ALL;
	ret = pthread_create(&thread, NULL, wait_thread, &thread_args);
	EXPECT_EQ(0, ret);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(ETIMEDOUT, ret);

	ret = ioctl(fd, WINESYNC_IOC_SET_EVENT, &event_args);
	EXPECT_EQ(0, ret);

	ret = wait_for_thread(thread, 100);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, thread_args.ret);
	EXPECT_EQ(2, wait_args.index);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &event_args.event);
	EXPECT_EQ(0, ret);

	/* test with an auto-reset event */

	event_args.manual = false;
	event_args.signaled = true;
	ret = ioctl(fd, WINESYNC_IOC_CREATE_EVENT, &event_args);
	EXPECT_EQ(0, ret);

	sem_args.sem = objs[1];
	sem_args.count = 2;
	ret = ioctl(fd, WINESYNC_IOC_PUT_SEM, &sem_args);
	EXPECT_EQ(0, ret);

	ret = wait_all_alert(fd, 2, objs, 123, event_args.event, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, index);

	ret = wait_all_alert(fd, 2, objs, 123, event_args.event, &index);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(2, index);

	ret = wait_all_alert(fd, 2, objs, 123, event_args.event, &index);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(ETIMEDOUT, errno);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &event_args.event);
	EXPECT_EQ(0, ret);

	ret = ioctl(fd, WINESYNC_IOC_DELETE, &objs[0]);
	EXPECT_EQ(0, ret);
	ret = ioctl(fd, WINESYNC_IOC_DELETE, &objs[1]);
	EXPECT_EQ(0, ret);

	close(fd);
}

TEST_HARNESS_MAIN
