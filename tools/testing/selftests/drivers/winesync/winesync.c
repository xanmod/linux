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

static int wait_any(int fd, __u32 count, const __u32 *objs, __u32 owner,
		    __u32 *index)
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
	ret = ioctl(fd, WINESYNC_IOC_WAIT_ANY, &args);
	*index = args.index;
	return ret;
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

TEST_HARNESS_MAIN
