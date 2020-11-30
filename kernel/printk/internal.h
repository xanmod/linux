/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * internal.h - printk internal definitions
 */

#ifdef CONFIG_PRINTK

/* Flags for a single printk record. */
enum printk_info_flags {
	LOG_NEWLINE	= 2,	/* text ended with a newline */
	LOG_CONT	= 8,	/* text is a fragment of a continuation line */
};

u16 printk_parse_prefix(const char *text, int *level,
			enum printk_info_flags *flags);
#endif /* CONFIG_PRINTK */
