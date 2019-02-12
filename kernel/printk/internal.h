/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * internal.h - printk internal definitions
 */
#include <linux/percpu.h>

#ifdef CONFIG_PRINTK

#define PRINTK_SAFE_CONTEXT_MASK	 0x3fffffff
#define PRINTK_NMI_DIRECT_CONTEXT_MASK	 0x40000000
#define PRINTK_NMI_CONTEXT_MASK		 0x80000000

extern raw_spinlock_t logbuf_lock;

__printf(5, 0)
int vprintk_store(int facility, int level,
		  const char *dict, size_t dictlen,
		  const char *fmt, va_list args);

__printf(1, 0) int vprintk_default(const char *fmt, va_list args);
__printf(1, 0) int vprintk_deferred(const char *fmt, va_list args);
__printf(1, 0) int vprintk_func(const char *fmt, va_list args);

void defer_console_output(void);

#else

__printf(1, 0) int vprintk_func(const char *fmt, va_list args) { return 0; }

/*
 * In !PRINTK builds we still export logbuf_lock spin_lock, console_sem
 * semaphore and some of console functions (console_unlock()/etc.), so
 * printk-safe must preserve the existing local IRQ guarantees.
 */
#endif /* CONFIG_PRINTK */

#define printk_safe_enter_irqsave(flags) local_irq_save(flags)
#define printk_safe_exit_irqrestore(flags) local_irq_restore(flags)

#define printk_safe_enter_irq() local_irq_disable()
#define printk_safe_exit_irq() local_irq_enable()
