// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2010 Werner Fink, Jiri Slaby
 */

#include <linux/console.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/tty_driver.h>

/*
 * This is handler for /proc/consoles
 */
static int show_console_dev(struct seq_file *m, void *v)
{
	static const struct {
		short flag;
		char name;
	} con_flags[] = {
		{ CON_ENABLED,		'E' },
		{ CON_CONSDEV,		'C' },
		{ CON_BOOT,		'B' },
		{ CON_NO_BKL,		'N' },
		{ CON_PRINTBUFFER,	'p' },
		{ CON_BRL,		'b' },
		{ CON_ANYTIME,		'a' },
	};
	char flags[ARRAY_SIZE(con_flags) + 1];
	struct console *con = v;
	char con_write = '-';
	unsigned int a;
	dev_t dev = 0;

	if (con->device) {
		const struct tty_driver *driver;
		int index;

		/*
		 * Take console_lock to serialize device() callback with
		 * other console operations. For example, fg_console is
		 * modified under console_lock when switching vt.
		 */
		console_lock();
		driver = con->device(con, &index);
		console_unlock();

		if (driver) {
			dev = MKDEV(driver->major, driver->minor_start);
			dev += index;
		}
	}

	for (a = 0; a < ARRAY_SIZE(con_flags); a++)
		flags[a] = (con->flags & con_flags[a].flag) ?
			con_flags[a].name : ' ';
	flags[a] = 0;

	seq_setwidth(m, 21 - 1);
	seq_printf(m, "%s%d", con->name, con->index);
	seq_pad(m, ' ');
	if (con->flags & CON_NO_BKL) {
		if (con->write_thread || con->write_atomic)
			con_write = 'W';
	} else {
		if (con->write)
			con_write = 'W';
	}
	seq_printf(m, "%c%c%c (%s)", con->read ? 'R' : '-', con_write,
		   con->unblank ? 'U' : '-', flags);
	if (dev)
		seq_printf(m, " %4d:%d", MAJOR(dev), MINOR(dev));

	seq_putc(m, '\n');
	return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	struct console *con;
	loff_t off = 0;

	/*
	 * Hold the console_list_lock to guarantee safe traversal of the
	 * console list. SRCU cannot be used because there is no
	 * place to store the SRCU cookie.
	 */
	console_list_lock();
	for_each_console(con)
		if (off++ == *pos)
			break;

	return con;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct console *con = v;

	++*pos;
	return hlist_entry_safe(con->node.next, struct console, node);
}

static void c_stop(struct seq_file *m, void *v)
{
	console_list_unlock();
}

static const struct seq_operations consoles_op = {
	.start	= c_start,
	.next	= c_next,
	.stop	= c_stop,
	.show	= show_console_dev
};

static int __init proc_consoles_init(void)
{
	proc_create_seq("consoles", 0, NULL, &consoles_op);
	return 0;
}
fs_initcall(proc_consoles_init);
