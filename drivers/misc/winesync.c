// SPDX-License-Identifier: GPL-2.0-only
/*
 * winesync.c - Kernel driver for Wine synchronization primitives
 *
 * Copyright (C) 2021 Zebediah Figura
 */

#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>

#define WINESYNC_NAME	"winesync"

static int winesync_char_open(struct inode *inode, struct file *file)
{
	return nonseekable_open(inode, file);
}

static int winesync_char_release(struct inode *inode, struct file *file)
{
	return 0;
}

static long winesync_char_ioctl(struct file *file, unsigned int cmd,
				unsigned long parm)
{
	switch (cmd) {
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
	.minor		= MISC_DYNAMIC_MINOR,
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
