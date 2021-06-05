// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/lsm_hooks.h>
#include <linux/sysctl.h>

/**
 * DOC: brute_ema_weight_numerator
 *
 * Weight's numerator of EMA.
 */
static unsigned int brute_ema_weight_numerator __read_mostly = 7;

/**
 * DOC: brute_ema_weight_denominator
 *
 * Weight's denominator of EMA.
 */
static unsigned int brute_ema_weight_denominator __read_mostly = 10;

/**
 * DOC: brute_max_faults
 *
 * Maximum number of faults.
 *
 * If a brute force attack is running slowly for a long time, the application
 * crash period's EMA is not suitable for the detection. This type of attack
 * must be detected using a maximum number of faults.
 */
static unsigned int brute_max_faults __read_mostly = 200;

/**
 * DOC: brute_min_faults
 *
 * Minimum number of faults.
 *
 * The application crash period's EMA cannot be used until a minimum number of
 * data has been applied to it. This constraint allows getting a trend when this
 * moving average is used.
 */
static unsigned int brute_min_faults __read_mostly = 5;

/**
 * DOC: brute_crash_period_threshold
 *
 * Application crash period threshold.
 *
 * A fast brute force attack is detected when the application crash period falls
 * below this threshold. The units are expressed in seconds.
 */
static unsigned int brute_crash_period_threshold __read_mostly = 30;

#ifdef CONFIG_SYSCTL
static unsigned int uint_max = UINT_MAX;
#define SYSCTL_UINT_MAX (&uint_max)

/*
 * brute_sysctl_path - Sysctl attributes path.
 */
static struct ctl_path brute_sysctl_path[] = {
	{ .procname = "kernel", },
	{ .procname = "brute", },
	{ }
};

/*
 * brute_sysctl_table - Sysctl attributes.
 */
static struct ctl_table brute_sysctl_table[] = {
	{
		.procname	= "ema_weight_numerator",
		.data		= &brute_ema_weight_numerator,
		.maxlen		= sizeof(brute_ema_weight_numerator),
		.mode		= 0644,
		.proc_handler	= proc_douintvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &brute_ema_weight_denominator,
	},
	{
		.procname	= "ema_weight_denominator",
		.data		= &brute_ema_weight_denominator,
		.maxlen		= sizeof(brute_ema_weight_denominator),
		.mode		= 0644,
		.proc_handler	= proc_douintvec_minmax,
		.extra1		= &brute_ema_weight_numerator,
		.extra2		= SYSCTL_UINT_MAX,
	},
	{
		.procname	= "max_faults",
		.data		= &brute_max_faults,
		.maxlen		= sizeof(brute_max_faults),
		.mode		= 0644,
		.proc_handler	= proc_douintvec_minmax,
		.extra1		= &brute_min_faults,
		.extra2		= SYSCTL_UINT_MAX,
	},
	{
		.procname	= "min_faults",
		.data		= &brute_min_faults,
		.maxlen		= sizeof(brute_min_faults),
		.mode		= 0644,
		.proc_handler	= proc_douintvec_minmax,
		.extra1		= SYSCTL_ONE,
		.extra2		= &brute_max_faults,
	},
	{
		.procname	= "crash_period_threshold",
		.data		= &brute_crash_period_threshold,
		.maxlen		= sizeof(brute_crash_period_threshold),
		.mode		= 0644,
		.proc_handler	= proc_douintvec_minmax,
		.extra1		= SYSCTL_ONE,
		.extra2		= SYSCTL_UINT_MAX,
	},
	{ }
};

/**
 * brute_init_sysctl() - Initialize the sysctl interface.
 */
static void __init brute_init_sysctl(void)
{
	if (!register_sysctl_paths(brute_sysctl_path, brute_sysctl_table))
		panic("sysctl registration failed\n");
}

#else
static inline void brute_init_sysctl(void) { }
#endif /* CONFIG_SYSCTL */

/**
 * brute_init() - Initialize the brute LSM.
 *
 * Return: Always returns zero.
 */
static int __init brute_init(void)
{
	pr_info("becoming mindful\n");
	brute_init_sysctl();
	return 0;
}

DEFINE_LSM(brute) = {
	.name = KBUILD_MODNAME,
	.init = brute_init,
};
