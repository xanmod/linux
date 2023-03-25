/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM pagemap

#if !defined(_TRACE_PAGEMAP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_PAGEMAP_H

#include <linux/tracepoint.h>
#include <linux/mm.h>

#define	PAGEMAP_MAPPED		0x0001u
#define PAGEMAP_ANONYMOUS	0x0002u
#define PAGEMAP_FILE		0x0004u
#define PAGEMAP_SWAPCACHE	0x0008u
#define PAGEMAP_SWAPBACKED	0x0010u
#define PAGEMAP_MAPPEDDISK	0x0020u
#define PAGEMAP_BUFFERS		0x0040u

#define trace_pagemap_flags(folio) ( \
	(folio_test_anon(folio)		? PAGEMAP_ANONYMOUS  : PAGEMAP_FILE) | \
	(folio_mapped(folio)		? PAGEMAP_MAPPED     : 0) | \
	(folio_test_swapcache(folio)	? PAGEMAP_SWAPCACHE  : 0) | \
	(folio_test_swapbacked(folio)	? PAGEMAP_SWAPBACKED : 0) | \
	(folio_test_mappedtodisk(folio)	? PAGEMAP_MAPPEDDISK : 0) | \
	(folio_test_private(folio)	? PAGEMAP_BUFFERS    : 0) \
	)

TRACE_EVENT(mm_lru_insertion,

	TP_PROTO(struct folio *folio),

	TP_ARGS(folio),

	TP_STRUCT__entry(
		__field(struct folio *,	folio	)
		__field(unsigned long,	pfn	)
		__field(enum lru_list,	lru	)
		__field(unsigned long,	flags	)
	/* DJL ADD BEGIN*/
		__field(int , gen	)
	/* DJL ADD END*/
	),

	TP_fast_assign(
		__entry->folio	= folio;
		__entry->pfn	= folio_pfn(folio);
		__entry->lru	= folio_lru_list(folio);
		__entry->flags	= trace_pagemap_flags(folio);
	/* DJL ADD BEGIN*/
		__entry->gen	= ((( READ_ONCE(folio->flags) & LRU_GEN_MASK) >> LRU_GEN_PGOFF) - 1);
	/* DJL ADD END*/
	),

	/* Flag format is based on page-types.c formatting for pagemap */
	TP_printk("folio=%p[%s] pfn=0x%lx lru=%d gen=%d flags=%s%s%s%s%s%s",
			__entry->folio,
			folio_test_transhuge(__entry->folio)? "T": "N",
			__entry->pfn,
			__entry->lru,
			__entry->gen,
			__entry->flags & PAGEMAP_MAPPED		? "M" : " ",
			__entry->flags & PAGEMAP_ANONYMOUS	? "a" : "f",
			__entry->flags & PAGEMAP_SWAPCACHE	? "s" : " ",
			__entry->flags & PAGEMAP_SWAPBACKED	? "b" : " ",
			__entry->flags & PAGEMAP_MAPPEDDISK	? "d" : " ",
			__entry->flags & PAGEMAP_BUFFERS	? "B" : " ")
);

TRACE_EVENT(mm_lru_activate,

	TP_PROTO(struct folio *folio),

	TP_ARGS(folio),

	TP_STRUCT__entry(
		__field(struct folio *,	folio	)
		__field(unsigned long,	pfn	)
	),

	TP_fast_assign(
		__entry->folio	= folio;
		__entry->pfn	= folio_pfn(folio);
	),

	TP_printk("folio=%p[%s] pfn=0x%lx", 
			__entry->folio,
			folio_test_transhuge(__entry->folio)? "T": "N", 
			__entry->pfn)
);

/*DJL ADD BEGIN*/
TRACE_EVENT(mm_lru_deactivate,

	TP_PROTO(struct folio *folio, int old_gen, int new_gen),

	TP_ARGS(folio, old_gen, new_gen),

	TP_STRUCT__entry(
		__field(struct folio *,	folio	)
		__field(unsigned long,	pfn	)
		__field(int,	old_gen	)
		__field(int,	new_gen	)
	),

	TP_fast_assign(
		__entry->folio	= folio;
		__entry->old_gen	= old_gen;
		__entry->new_gen	= new_gen;
		__entry->pfn	= folio_pfn(folio);
	),

	TP_printk("folio=%p[%s] gen:%d->%d pfn=0x%lx", 
			__entry->folio,
			folio_test_transhuge(__entry->folio)? "T": "N", 
			__entry->old_gen,
			__entry->new_gen,
			__entry->pfn)
);
/*DJL ADD END*/
#endif /* _TRACE_PAGEMAP_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
