// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * printk_safe.c - Safe printk for printk-deadlock-prone contexts
 */

#include <linux/preempt.h>
#include <linux/kdb.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/printk.h>
#include <linux/kprobes.h>

#include "internal.h"

struct printk_context {
	local_lock_t cpu;
	int recursion;
};

static DEFINE_PER_CPU(struct printk_context, printk_context) = {
	.cpu = INIT_LOCAL_LOCK(cpu),
};

/* Can be preempted by NMI. */
void __printk_safe_enter(unsigned long *flags)
{
	WARN_ON_ONCE(in_nmi());
	local_lock_irqsave(&printk_context.cpu, *flags);
	this_cpu_inc(printk_context.recursion);
}

/* Can be preempted by NMI. */
void __printk_safe_exit(unsigned long *flags)
{
	WARN_ON_ONCE(in_nmi());
	this_cpu_dec(printk_context.recursion);
	local_unlock_irqrestore(&printk_context.cpu, *flags);
}

void __printk_deferred_enter(void)
{
	WARN_ON_ONCE(!in_atomic());
	this_cpu_inc(printk_context.recursion);
}

void __printk_deferred_exit(void)
{
	WARN_ON_ONCE(!in_atomic());
	this_cpu_dec(printk_context.recursion);
}

asmlinkage int vprintk(const char *fmt, va_list args)
{
#ifdef CONFIG_KGDB_KDB
	/* Allow to pass printk() to kdb but avoid a recursion. */
	if (unlikely(kdb_trap_printk && kdb_printf_cpu < 0))
		return vkdb_printf(KDB_MSGSRC_PRINTK, fmt, args);
#endif

	/*
	 * Use the main logbuf even in NMI. But avoid calling console
	 * drivers that might have their own locks.
	 */
	if (this_cpu_read(printk_context.recursion) || in_nmi())
		return vprintk_deferred(fmt, args);

	/* No obstacles. */
	return vprintk_default(fmt, args);
}
EXPORT_SYMBOL(vprintk);
