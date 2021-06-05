// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/binfmts.h>
#include <linux/lsm_hooks.h>
#include <linux/sysctl.h>
#include <linux/xattr.h>
#include <net/ipv6.h>
#include <net/sock.h>

/**
 * struct brute_stats - Fork brute force attack statistics.
 * @faults: Number of crashes.
 * @nsecs: Last crash timestamp as the number of nanoseconds in the
 *         International Atomic Time (TAI) reference.
 * @period: Crash period's moving average.
 * @flags: Statistics flags as a whole.
 * @not_allowed: Not allowed executable file flag.
 * @unused: Remaining unused flags.
 *
 * This structure holds the statistical data shared by all the fork hierarchy
 * processes.
 */
struct brute_stats {
	u32 faults;
	u64 nsecs;
	u64 period;
	union {
		u8 flags;
		struct {
			u8 not_allowed : 1;
			u8 unused : 7;
		};
	};
};

/**
 * struct brute_raw_stats - Raw fork brute force attack statistics.
 * @faults: Number of crashes.
 * @nsecs: Last crash timestamp as the number of nanoseconds in the
 *         International Atomic Time (TAI) reference.
 * @period: Crash period's moving average.
 * @flags: Statistics flags.
 *
 * This structure holds the statistical data on disk as an extended attribute.
 * Since the filesystems on which extended attributes are stored might also be
 * used on architectures with a different byte order and machine word size, care
 * should be taken to store attribute values in an architecture-independent
 * format.
 */
struct brute_raw_stats {
	__le32 faults;
	__le64 nsecs;
	__le64 period;
	u8 flags;
} __packed;

/**
 * struct brute_task - Task info.
 * @killed: Task killed to mitigate a brute force attack.
 */
struct brute_task {
	u8 killed : 1;
};

/*
 * brute_blob_sizes - LSM blob sizes.
 */
static struct lsm_blob_sizes brute_blob_sizes __lsm_ro_after_init = {
	.lbs_task = sizeof(struct brute_task),
};

/**
 * brute_task() - Get the task info.
 * @task: The task to get the info.
 *
 * Return: A pointer to the brute_task structure.
 */
static inline struct brute_task *brute_task(const struct task_struct *task)
{
	return task->security + brute_blob_sizes.lbs_task;
}

/**
 * brute_set_task_killed() - Set task killed to mitigate a brute force attack.
 * @task: The task to set.
 */
static inline void brute_set_task_killed(struct task_struct *task)
{
	struct brute_task *task_info;

	task_info = brute_task(task);
	task_info->killed = true;
}

/**
 * brute_task_killed() - Test if a task has been killed to mitigate an attack.
 * @task: The task to test.
 *
 * Return: True if the task has been killed to mitigate a brute force attack.
 *         False otherwise.
 */
inline bool brute_task_killed(const struct task_struct *task)
{
	struct brute_task *task_info;

	task_info = brute_task(task);
	return task_info->killed;
}

/**
 * brute_get_current_exe_file() - Get the current task's executable file.
 *
 * Since all the kernel threads associated with a task share the same executable
 * file, get the thread group leader's executable file.
 *
 * Context: The file must be released via fput().
 * Return: NULL if the current task has no associated executable file. A pointer
 *         to the executable file otherwise.
 */
static struct file *brute_get_current_exe_file(void)
{
	struct task_struct *task = current;
	struct file *exe_file;

	rcu_read_lock();
	if (!thread_group_leader(task))
		task = rcu_dereference(task->group_leader);
	get_task_struct(task);
	rcu_read_unlock();

	exe_file = get_task_exe_file(task);
	put_task_struct(task);
	return exe_file;
}

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
 * brute_mul_by_ema_weight() - Multiply by EMA weight.
 * @value: Value to multiply by EMA weight.
 *
 * Return: The result of the multiplication operation.
 */
static inline u64 brute_mul_by_ema_weight(u64 value)
{
	return mul_u64_u32_div(value, brute_ema_weight_numerator,
			       brute_ema_weight_denominator);
}

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
 * brute_update_crash_period() - Update the application crash period.
 * @stats: Statistics that hold the application crash period to update. Cannot
 *         be NULL.
 *
 * The application crash period must be a value that is not prone to change due
 * to spurious data and follows the real crash period. So, to compute it, the
 * exponential moving average (EMA) is used.
 *
 * This kind of average defines a weight (between 0 and 1) for the new value to
 * add and applies the remainder of the weight to the current average value.
 * This way, some spurious data will not excessively modify the average and only
 * if the new values are persistent, the moving average will tend towards them.
 *
 * Mathematically the application crash period's EMA can be expressed as
 * follows:
 *
 * period_ema = period * weight + period_ema * (1 - weight)
 *
 * If the operations are applied:
 *
 * period_ema = period * weight + period_ema - period_ema * weight
 *
 * If the operands are ordered:
 *
 * period_ema = period_ema - period_ema * weight + period * weight
 *
 * Finally, this formula can be written as follows:
 *
 * period_ema -= period_ema * weight;
 * period_ema += period * weight;
 */
static void brute_update_crash_period(struct brute_stats *stats)
{
	u64 current_period;
	u64 now = ktime_get_clocktai_ns();

	if (stats->faults >= (u32)brute_max_faults)
		return;

	if (stats->nsecs) {
		current_period = now > stats->nsecs ? now - stats->nsecs : 0;
		stats->period -= brute_mul_by_ema_weight(stats->period);
		stats->period += brute_mul_by_ema_weight(current_period);
	}

	stats->nsecs = now;
	stats->faults += 1;
}

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

/**
 * brute_attack_running() - Test if a brute force attack is happening.
 * @stats: Statistical data shared by all the fork hierarchy processes. Cannot
 *         be NULL.
 *
 * The decision if a brute force attack is running is based on the statistical
 * data shared by all the fork hierarchy processes.
 *
 * There are two types of brute force attacks that can be detected using the
 * statistical data. The first one is a slow brute force attack that is detected
 * if the maximum number of faults per fork hierarchy is reached. The second
 * type is a fast brute force attack that is detected if the application crash
 * period falls below a certain threshold.
 *
 * Moreover, it is important to note that no attacks will be detected until a
 * minimum number of faults have occurred. This allows to have a trend in the
 * crash period when the EMA is used.
 *
 * Return: True if a brute force attack is happening. False otherwise.
 */
static bool brute_attack_running(const struct brute_stats *stats)
{
	u64 threshold;

	if (stats->faults < (u32)brute_min_faults)
		return false;

	if (stats->faults >= (u32)brute_max_faults)
		return true;

	threshold = (u64)brute_crash_period_threshold * (u64)NSEC_PER_SEC;
	return stats->period < threshold;
}

/**
 * brute_print_attack_running() - Warn about a fork brute force attack.
 */
static inline void brute_print_attack_running(void)
{
	pr_warn("fork brute force attack detected [pid %d: %s]\n", current->pid,
		current->comm);
}

/**
 * brute_print_file_not_allowed() - Warn about a file not allowed.
 * @dentry: The dentry of the file not allowed.
 */
static void brute_print_file_not_allowed(struct dentry *dentry)
{
	char *buf, *path;

	buf = __getname();
	if (WARN_ON_ONCE(!buf))
		return;

	path = dentry_path_raw(dentry, buf, PATH_MAX);
	if (WARN_ON_ONCE(IS_ERR(path)))
		goto free;

	pr_warn_ratelimited("%s not allowed\n", path);
free:
	__putname(buf);
}

/**
 * brute_is_same_file() - Test if two files are the same.
 * @file1: First file to compare. Cannot be NULL.
 * @file2: Second file to compare. Cannot be NULL.
 *
 * Two files are the same if they have the same inode number and the same block
 * device.
 *
 * Return: True if the two files are the same. False otherwise.
 */
static inline bool brute_is_same_file(const struct file *file1,
				      const struct file *file2)
{
	struct inode *inode1 = file_inode(file1);
	struct inode *inode2 = file_inode(file2);

	return inode1->i_ino == inode2->i_ino &&
		inode1->i_sb->s_dev == inode2->i_sb->s_dev;
}

/**
 * brute_kill_offending_tasks() - Kill the offending tasks.
 * @file: The file executed during a brute force attack. Cannot be NULL.
 *
 * When a brute force attack is detected all the offending tasks involved in the
 * attack must be killed. In other words, it is necessary to kill all the tasks
 * that are executing the same file that is running during the brute force
 * attack. Moreover, the processes that have the same group_leader that the
 * current task must be avoided since they are in the path to be killed.
 *
 * The for_each_process loop is protected by the tasklist_lock acquired in read
 * mode instead of rcu_read_lock to avoid that the newly created processes
 * escape this RCU read lock.
 */
static void brute_kill_offending_tasks(const struct file *file)
{
	struct task_struct *task;
	struct file *exe_file;
	bool is_same_file;

	read_lock(&tasklist_lock);
	for_each_process(task) {
		if (task->group_leader == current->group_leader) {
			brute_set_task_killed(task);
			continue;
		}

		exe_file = get_task_exe_file(task);
		if (!exe_file)
			continue;

		is_same_file = brute_is_same_file(exe_file, file);
		fput(exe_file);
		if (!is_same_file)
			continue;

		do_send_sig_info(SIGKILL, SEND_SIG_PRIV, task, PIDTYPE_PID);
		pr_warn_ratelimited("offending process %d [%s] killed\n",
				    task->pid, task->comm);
		brute_set_task_killed(task);
	}
	read_unlock(&tasklist_lock);
}

/**
 * brute_get_xattr_stats() - Get the stats from an extended attribute.
 * @dentry: The dentry of the file to get the extended attribute.
 * @inode: The inode of the file to get the extended attribute.
 * @stats: The stats where to store the info obtained from the extended
 *         attribute. Cannot be NULL.
 *
 * Return: An error code if it is not possible to get the statistical data. Zero
 *         otherwise.
 */
static int brute_get_xattr_stats(struct dentry *dentry, struct inode *inode,
				 struct brute_stats *stats)
{
	int rc;
	struct brute_raw_stats raw_stats;

	rc = __vfs_getxattr(dentry, inode, XATTR_NAME_BRUTE, &raw_stats,
			    sizeof(raw_stats));
	if (rc < 0)
		return rc;

	stats->faults = le32_to_cpu(raw_stats.faults);
	stats->nsecs = le64_to_cpu(raw_stats.nsecs);
	stats->period = le64_to_cpu(raw_stats.period);
	stats->flags = raw_stats.flags;
	return 0;
}

/**
 * brute_set_xattr_stats() - Set the stats to an extended attribute.
 * @dentry: The dentry of the file to set the extended attribute.
 * @inode: The inode of the file to set the extended attribute.
 * @stats: The stats from where to extract the info to set the extended attribute.
 *         Cannot be NULL.
 *
 * Return: An error code if it is not possible to set the statistical data. Zero
 *         otherwise.
 */
static int brute_set_xattr_stats(struct dentry *dentry, struct inode *inode,
				 const struct brute_stats *stats)
{
	struct brute_raw_stats raw_stats;

	raw_stats.faults = cpu_to_le32(stats->faults);
	raw_stats.nsecs = cpu_to_le64(stats->nsecs);
	raw_stats.period = cpu_to_le64(stats->period);
	raw_stats.flags = stats->flags;

	return __vfs_setxattr(&init_user_ns, dentry, inode, XATTR_NAME_BRUTE,
			      &raw_stats, sizeof(raw_stats), 0);
}

/**
 * brute_update_xattr_stats() - Update the stats of a file.
 * @file: The file that holds the statistical data to update. Cannot be NULL.
 *
 * For a correct management of a fork brute force attack it is only necessary to
 * update the statistics and test if an attack is happening based on these data.
 * It is important to note that if the file has no stats nothing is updated nor
 * created. This way, the scenario where an application has not crossed any
 * privilege boundary is avoided since the existence of the extended attribute
 * denotes the crossing of bounds.
 *
 * Also, do not update the statistics if the execution of the file is not
 * allowed and kill all the offending tasks when a brute force attack is
 * detected.
 */
static void brute_update_xattr_stats(const struct file *file)
{
	struct dentry *dentry = file_dentry(file);
	struct inode *inode = file_inode(file);
	struct brute_stats stats;
	int rc;

	inode_lock(inode);
	rc = brute_get_xattr_stats(dentry, inode, &stats);
	WARN_ON_ONCE(rc && rc != -ENODATA);
	if (rc || (!rc && stats.not_allowed)) {
		inode_unlock(inode);
		return;
	}

	brute_update_crash_period(&stats);
	if (brute_attack_running(&stats)) {
		brute_print_attack_running();
		stats.not_allowed = true;
	}

	rc = brute_set_xattr_stats(dentry, inode, &stats);
	WARN_ON_ONCE(rc);
	inode_unlock(inode);

	if (stats.not_allowed)
		brute_kill_offending_tasks(file);
}

/**
 * brute_reset_stats() - Reset the statistical data.
 * @stats: Statistics to be reset. Cannot be NULL.
 */
static inline void brute_reset_stats(struct brute_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
}

/**
 * brute_new_xattr_stats() - New statistics for a file.
 * @file: The file in which to create the new statistical data. Cannot be NULL.
 *
 * Only if the file has no statistical data create it. This function will be
 * called to mark that a privilege boundary has been crossed so, if new stats
 * are required, they do not contain any useful data. The existence of the
 * extended attribute denotes the crossing of privilege bounds.
 *
 * Return: An error code if it is not possible to get or set the statistical
 *         data. Zero otherwise.
 */
static int brute_new_xattr_stats(const struct file *file)
{
	struct dentry *dentry = file_dentry(file);
	struct inode *inode = file_inode(file);
	struct brute_stats stats;
	int rc;

	inode_lock(inode);
	rc = brute_get_xattr_stats(dentry, inode, &stats);
	if (rc && rc != -ENODATA)
		goto unlock;

	if (rc == -ENODATA) {
		brute_reset_stats(&stats);
		rc = brute_set_xattr_stats(dentry, inode, &stats);
		if (rc)
			goto unlock;
	}

unlock:
	inode_unlock(inode);
	return rc;
}

/**
 * brute_current_new_xattr_stats() - New stats for the current task's exe file.
 *
 * Return: An error code if it is not possible to get or set the statistical
 *         data. Zero otherwise.
 */
static int brute_current_new_xattr_stats(void)
{
	struct file *exe_file;
	int rc;

	exe_file = brute_get_current_exe_file();
	if (WARN_ON_ONCE(!exe_file))
		return -ENOENT;

	rc = brute_new_xattr_stats(exe_file);
	WARN_ON_ONCE(rc);
	fput(exe_file);
	return rc;
}

/**
 * brute_signal_from_user() - Test if a signal is coming from userspace.
 * @siginfo: Contains the signal information.
 *
 * To avoid false positives during the attack detection it is necessary to
 * narrow the possible cases. So, only the signals delivered by the kernel are
 * taken into account with the exception of the SIGABRT signal since the latter
 * is used by glibc for stack canary, malloc, etc failures, which may indicate
 * that a mitigation has been triggered.
 *
 * Return: True if the signal is coming from usersapce. False otherwise.
 */
static inline bool brute_signal_from_user(const kernel_siginfo_t *siginfo)
{
	return siginfo->si_signo == SIGKILL && siginfo->si_code != SIGABRT;
}

/**
 * brute_task_fatal_signal() - Target for the task_fatal_signal hook.
 * @siginfo: Contains the signal information.
 *
 * To detect a brute force attack it is necessary, as a first step, to test in
 * every fatal crash if the signal is delibered by the kernel. If so, update the
 * statistics and act based on these data.
 */
static void brute_task_fatal_signal(const kernel_siginfo_t *siginfo)
{
	struct file *exe_file;

	if (brute_signal_from_user(siginfo))
		return;

	exe_file = brute_get_current_exe_file();
	if (WARN_ON_ONCE(!exe_file))
		return;

	brute_update_xattr_stats(exe_file);
	fput(exe_file);
}

/**
 * brute_task_execve() - Target for the bprm_creds_from_file hook.
 * @bprm: Contains the linux_binprm structure.
 * @file: Binary that will be executed without an interpreter.
 *
 * If there are statistics, test the "not_allowed" flag and avoid the file
 * execution based on this. Also, this hook is useful to mark that a privilege
 * boundary (setuid/setgid process) has been crossed. This is done based on the
 * "secureexec" flag.
 *
 * To be defensive return an error code if it is not possible to get or set the
 * stats using an extended attribute since this blocks the execution of the
 * file. This scenario is treated as an attack.
 *
 * Return: -EPERM if the execution of the file is not allowed. An error code if
 *         it is not possible to get or set the statistical data. Zero otherwise.
 */
static int brute_task_execve(struct linux_binprm *bprm, struct file *file)
{
	struct dentry *dentry = file_dentry(bprm->file);
	struct inode *inode = file_inode(bprm->file);
	struct brute_stats stats;
	int rc;

	inode_lock(inode);
	rc = brute_get_xattr_stats(dentry, inode, &stats);
	if (WARN_ON_ONCE(rc && rc != -ENODATA))
		goto unlock;

	if (!rc && stats.not_allowed) {
		brute_print_file_not_allowed(dentry);
		rc = -EPERM;
		goto unlock;
	}

	if (rc == -ENODATA && bprm->secureexec) {
		brute_reset_stats(&stats);
		rc = brute_set_xattr_stats(dentry, inode, &stats);
		if (WARN_ON_ONCE(rc))
			goto unlock;
	}

	rc = 0;
unlock:
	inode_unlock(inode);
	return rc;
}

/**
 * brute_task_change_priv() - Target for the task_fix_setid hooks.
 * @new: The set of credentials that will be installed.
 * @old: The set of credentials that are being replaced.
 * @flags: Contains one of the LSM_SETID_* values.
 *
 * This hook is useful to mark that a privilege boundary (privilege changes) has
 * been crossed.
 *
 * Return: An error code if it is not possible to get or set the statistical
 *         data. Zero otherwise.
 */
static int brute_task_change_priv(struct cred *new, const struct cred *old, int flags)
{
	return brute_current_new_xattr_stats();
}

#ifdef CONFIG_IPV6
/**
 * brute_local_ipv6_rcv_saddr() - Test if an ipv6 rcv_saddr is local.
 * @sk: The sock that contains the ipv6 address.
 *
 * Return: True if the ipv6 rcv_saddr is local. False otherwise.
 */
static inline bool brute_local_ipv6_rcv_saddr(const struct sock *sk)
{
	return ipv6_addr_equal(&sk->sk_v6_rcv_saddr, &in6addr_loopback);
}
#else
static inline bool brute_local_ipv6_rcv_saddr(const struct sock *sk)
{
	return false;
}
#endif /* CONFIG_IPV6 */

#ifdef CONFIG_SECURITY_NETWORK
/**
 * brute_socket_accept() - Target for the socket_accept hook.
 * @sock: Contains the listening socket structure.
 * @newsock: Contains the newly created server socket for connection.
 *
 * This hook is useful to mark that a privilege boundary (network to local) has
 * been crossed. This is done only if the listening socket accepts external
 * connections. The sockets for inter-process communication (IPC) and those that
 * are listening on loopback addresses are not taken into account.
 *
 * Return: An error code if it is not possible to get or set the statistical
 *         data. Zero otherwise.
 */
static int brute_socket_accept(struct socket *sock, struct socket *newsock)
{
	struct sock *sk = sock->sk;

	if (sk->sk_family == AF_UNIX || sk->sk_family == AF_NETLINK ||
	    sk->sk_rcv_saddr == htonl(INADDR_LOOPBACK) ||
	    brute_local_ipv6_rcv_saddr(sk))
		return 0;

	return brute_current_new_xattr_stats();
}
#endif /* CONFIG_SECURITY_NETWORK */

/*
 * brute_hooks - Targets for the LSM's hooks.
 */
static struct security_hook_list brute_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(task_fatal_signal, brute_task_fatal_signal),
	LSM_HOOK_INIT(bprm_creds_from_file, brute_task_execve),
	LSM_HOOK_INIT(task_fix_setuid, brute_task_change_priv),
	LSM_HOOK_INIT(task_fix_setgid, brute_task_change_priv),
#ifdef CONFIG_SECURITY_NETWORK
	LSM_HOOK_INIT(socket_accept, brute_socket_accept),
#endif
};

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
	security_add_hooks(brute_hooks, ARRAY_SIZE(brute_hooks),
			   KBUILD_MODNAME);
	brute_init_sysctl();
	return 0;
}

DEFINE_LSM(brute) = {
	.name = KBUILD_MODNAME,
	.init = brute_init,
	.blobs = &brute_blob_sizes,
};
