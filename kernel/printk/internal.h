/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * internal.h - printk internal definitions
 */
#include <linux/percpu.h>
#include <linux/console.h>
#include "printk_ringbuffer.h"

#if defined(CONFIG_PRINTK) && defined(CONFIG_SYSCTL)
void __init printk_sysctl_init(void);
int devkmsg_sysctl_set_loglvl(struct ctl_table *table, int write,
			      void *buffer, size_t *lenp, loff_t *ppos);
#else
#define printk_sysctl_init() do { } while (0)
#endif

#define con_printk(lvl, con, fmt, ...)				\
	printk(lvl pr_fmt("%s%sconsole [%s%d] " fmt),		\
	       (con->flags & CON_NO_BKL) ? "" : "legacy ",	\
	       (con->flags & CON_BOOT) ? "boot" : "",		\
	       con->name, con->index, ##__VA_ARGS__)

#ifdef CONFIG_PRINTK
#ifdef CONFIG_PRINTK_CALLER
#define PRINTK_PREFIX_MAX	48
#else
#define PRINTK_PREFIX_MAX	32
#endif

/*
 * the maximum size of a formatted record (i.e. with prefix added
 * per line and dropped messages or in extended message format)
 */
#define PRINTK_MESSAGE_MAX	2048

/* the maximum size allowed to be reserved for a record */
#define PRINTKRB_RECORD_MAX	1024

/* Flags for a single printk record. */
enum printk_info_flags {
	LOG_NEWLINE	= 2,	/* text ended with a newline */
	LOG_CONT	= 8,	/* text is a fragment of a continuation line */
};

extern struct printk_ringbuffer *prb;
extern bool have_bkl_console;
extern bool printk_threads_enabled;

extern bool have_boot_console;

__printf(4, 0)
int vprintk_store(int facility, int level,
		  const struct dev_printk_info *dev_info,
		  const char *fmt, va_list args);

__printf(1, 0) int vprintk_default(const char *fmt, va_list args);
__printf(1, 0) int vprintk_deferred(const char *fmt, va_list args);

bool printk_percpu_data_ready(void);

/*
 * The printk_safe_enter()/_exit() macros mark code blocks using locks that
 * would lead to deadlock if an interrupting context were to call printk()
 * while the interrupted context was within such code blocks.
 *
 * When a CPU is in such a code block, an interrupting context calling
 * printk() will only log the new message to the lockless ringbuffer and
 * then trigger console printing using irqwork.
 */

#define printk_safe_enter_irqsave(flags)	\
	do {					\
		__printk_safe_enter(&flags);	\
	} while (0)

#define printk_safe_exit_irqrestore(flags)	\
	do {					\
		__printk_safe_exit(&flags);	\
	} while (0)

void defer_console_output(void);

u16 printk_parse_prefix(const char *text, int *level,
			enum printk_info_flags *flags);

u64 cons_read_seq(struct console *con);
void cons_nobkl_cleanup(struct console *con);
bool cons_nobkl_init(struct console *con);
bool cons_alloc_percpu_data(struct console *con);
void cons_kthread_create(struct console *con);
void cons_wake_threads(void);
void cons_force_seq(struct console *con, u64 seq);
void console_bkl_kthread_create(void);

/*
 * Check if the given console is currently capable and allowed to print
 * records. If the caller only works with certain types of consoles, the
 * caller is responsible for checking the console type before calling
 * this function.
 */
static inline bool console_is_usable(struct console *con, short flags)
{
	if (!(flags & CON_ENABLED))
		return false;

	if ((flags & CON_SUSPENDED))
		return false;

	/*
	 * The usability of a console varies depending on whether
	 * it is a NOBKL console or not.
	 */

	if (flags & CON_NO_BKL) {
		if (have_boot_console)
			return false;

	} else {
		if (!con->write)
			return false;
		/*
		 * Console drivers may assume that per-cpu resources have
		 * been allocated. So unless they're explicitly marked as
		 * being able to cope (CON_ANYTIME) don't call them until
		 * this CPU is officially up.
		 */
		if (!cpu_online(raw_smp_processor_id()) && !(flags & CON_ANYTIME))
			return false;
	}

	return true;
}

/**
 * cons_kthread_wake - Wake up a printk thread
 * @con:        Console to operate on
 */
static inline void cons_kthread_wake(struct console *con)
{
	rcuwait_wake_up(&con->rcuwait);
}

#else

#define PRINTK_PREFIX_MAX	0
#define PRINTK_MESSAGE_MAX	0
#define PRINTKRB_RECORD_MAX	0

static inline void cons_kthread_wake(struct console *con) { }
static inline void cons_kthread_create(struct console *con) { }
#define printk_threads_enabled	(false)

/*
 * In !PRINTK builds we still export console_sem
 * semaphore and some of console functions (console_unlock()/etc.), so
 * printk-safe must preserve the existing local IRQ guarantees.
 */
#define printk_safe_enter_irqsave(flags) local_irq_save(flags)
#define printk_safe_exit_irqrestore(flags) local_irq_restore(flags)

static inline bool printk_percpu_data_ready(void) { return false; }
static inline bool cons_nobkl_init(struct console *con) { return true; }
static inline void cons_nobkl_cleanup(struct console *con) { }
static inline bool console_is_usable(struct console *con, short flags) { return false; }
static inline void cons_force_seq(struct console *con, u64 seq) { }

#endif /* CONFIG_PRINTK */

extern bool have_boot_console;

/**
 * struct printk_buffers - Buffers to read/format/output printk messages.
 * @outbuf:	After formatting, contains text to output.
 * @scratchbuf:	Used as temporary ringbuffer reading and string-print space.
 */
struct printk_buffers {
	char	outbuf[PRINTK_MESSAGE_MAX];
	char	scratchbuf[PRINTKRB_RECORD_MAX];
};

/**
 * struct printk_message - Container for a prepared printk message.
 * @pbufs:	printk buffers used to prepare the message.
 * @outbuf_len:	The length of prepared text in @pbufs->outbuf to output. This
 *		does not count the terminator. A value of 0 means there is
 *		nothing to output and this record should be skipped.
 * @seq:	The sequence number of the record used for @pbufs->outbuf.
 * @dropped:	The number of dropped records from reading @seq.
 */
struct printk_message {
	struct printk_buffers	*pbufs;
	unsigned int		outbuf_len;
	u64			seq;
	unsigned long		dropped;
};

/**
 * struct cons_context_data - console context data
 * @wctxt:		Write context per priority level
 * @pbufs:		Buffer for storing the text
 *
 * Used for early boot and for per CPU data.
 *
 * The write contexts are allocated to avoid having them on stack, e.g. in
 * warn() or panic().
 */
struct cons_context_data {
	struct cons_write_context	wctxt[CONS_PRIO_MAX];
	struct printk_buffers	pbufs;
};

bool printk_get_next_message(struct printk_message *pmsg, u64 seq,
			     bool is_extended, bool may_supress);

#ifdef CONFIG_PRINTK

void console_prepend_dropped(struct printk_message *pmsg,
			     unsigned long dropped);

#endif

bool other_cpu_in_panic(void);
