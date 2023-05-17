/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM lru_gen

#if !defined(_TRACE_LRU_GEN_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_LRU_GEN_H

#include <linux/tracepoint.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>

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

TRACE_EVENT(mglru_folio_updt_gen,

	TP_PROTO(struct folio *folio, int oldgen, int newgen),

	TP_ARGS(folio, oldgen, newgen),

	TP_STRUCT__entry(
		__field(struct folio *,	folio	)
		__field(unsigned long,	pfn	)
		__field(int , oldgen    )
		__field(int , newgen    )
		__field(unsigned long,	flags	)
	),

	TP_fast_assign(
		__entry->folio	= folio;
		__entry->pfn	= folio_pfn(folio);
		__entry->oldgen	= oldgen;
		__entry->newgen	= newgen;
		__entry->flags	= trace_pagemap_flags(folio);
	),

	/* Flag format is based on page-types.c formatting for pagemap */
	TP_printk("folio=%p[%s] pfn=0x%lx gen:%d->%d flags=%s%s%s%s%s%s",
			__entry->folio,
			folio_test_transhuge(__entry->folio)? "T": "N",
			__entry->pfn,
			__entry->oldgen,
			__entry->newgen,
			__entry->flags & PAGEMAP_MAPPED		? "M" : " ",
			__entry->flags & PAGEMAP_ANONYMOUS	? "a" : "f",
			__entry->flags & PAGEMAP_SWAPCACHE	? "s" : " ",
			__entry->flags & PAGEMAP_SWAPBACKED	? "b" : " ",
			__entry->flags & PAGEMAP_MAPPEDDISK	? "d" : " ",
			__entry->flags & PAGEMAP_BUFFERS	? "B" : " ")
);

TRACE_EVENT(mglru_folio_inc_gen,

	TP_PROTO(struct folio *folio, int oldgen, int newgen),

	TP_ARGS(folio, oldgen, newgen),

	TP_STRUCT__entry(
		__field(struct folio *,	folio	)
		__field(unsigned long,	pfn	)
		__field(int , oldgen    )
		__field(int , newgen    )
		__field(unsigned long,	flags	)
	),

	TP_fast_assign(
		__entry->folio	= folio;
		__entry->pfn	= folio_pfn(folio);
		__entry->oldgen	= oldgen;
		__entry->newgen	= newgen;
		__entry->flags	= trace_pagemap_flags(folio);
	),

	/* Flag format is based on page-types.c formatting for pagemap */
	TP_printk("folio=%p[%s] pfn=0x%lx gen:%d->%d flags=%s%s%s%s%s%s",
			__entry->folio,
			folio_test_transhuge(__entry->folio)? "T": "N",
			__entry->pfn,
			__entry->oldgen,
			__entry->newgen,
			__entry->flags & PAGEMAP_MAPPED		? "M" : " ",
			__entry->flags & PAGEMAP_ANONYMOUS	? "a" : "f",
			__entry->flags & PAGEMAP_SWAPCACHE	? "s" : " ",
			__entry->flags & PAGEMAP_SWAPBACKED	? "b" : " ",
			__entry->flags & PAGEMAP_MAPPEDDISK	? "d" : " ",
			__entry->flags & PAGEMAP_BUFFERS	? "B" : " ")
);

TRACE_EVENT(mglru_isolate_folio,

	TP_PROTO(struct lruvec *lruvec, struct folio *folio, int gen, int success),

	TP_ARGS(lruvec, folio, gen, success),

	TP_STRUCT__entry(
		__field(struct lruvec *, lruvec	)
		__field(struct folio *,	folio	)
		__field(unsigned long,	pfn	)
		__field(int , success    )
		__field(int , gen    )
		__field(unsigned long,	flags	)
	),

	TP_fast_assign(
		__entry->lruvec	= lruvec;
		__entry->folio	= folio;
		__entry->pfn	= folio_pfn(folio);
		__entry->gen	= gen;
		__entry->success	= success;
		__entry->flags	= trace_pagemap_flags(folio);
	),

	/* Flag format is based on page-types.c formatting for pagemap */
	TP_printk("lruvec=%p folio=%p[%s] pfn=0x%lx gen:%d success=%d flags=%s%s%s%s%s%s",
			__entry->lruvec,
			__entry->folio,
			folio_test_transhuge(__entry->folio)? "T": "N",
			__entry->pfn,
			__entry->gen,
			__entry->success,
			__entry->flags & PAGEMAP_MAPPED		? "M" : " ",
			__entry->flags & PAGEMAP_ANONYMOUS	? "a" : "f",
			__entry->flags & PAGEMAP_SWAPCACHE	? "s" : " ",
			__entry->flags & PAGEMAP_SWAPBACKED	? "b" : " ",
			__entry->flags & PAGEMAP_MAPPEDDISK	? "d" : " ",
			__entry->flags & PAGEMAP_BUFFERS	? "B" : " ")
);

TRACE_EVENT(mglru_sort_folio,

	TP_PROTO(struct lruvec *lruvec, struct folio *folio, int gen, int reason),

	TP_ARGS(lruvec, folio, gen, reason),

	TP_STRUCT__entry(
		__field(struct lruvec *, lruvec	)
		__field(struct folio *,	folio	)
		__field(unsigned long,	pfn	)
		__field(int , reason    )
		__field(int , gen    )
		__field(unsigned long,	flags	)
	),

	TP_fast_assign(
		__entry->lruvec	= lruvec;
		__entry->folio	= folio;
		__entry->pfn	= folio_pfn(folio);
		__entry->gen	= gen;
		__entry->reason	= reason;
		__entry->flags	= trace_pagemap_flags(folio);
	),

	/* Flag format is based on page-types.c formatting for pagemap */
	TP_printk("[%s]lruvec=%p folio=%p[%s] pfn=0x%lx gen:%d  flags=%s%s%s%s%s%s",
			(__entry->reason == 0 )? "KILLED" : (
			(__entry->reason == 1 )? "unevictable" : (
			(__entry->reason == 2 )? "dirty lazyfree" : (
			(__entry->reason == 3 )? "promoted" : (
			(__entry->reason == 4 )? "protected" : "writeback" 
			)))),
			__entry->lruvec,
			__entry->folio,
			folio_test_transhuge(__entry->folio)? "T": "N",
			__entry->pfn,
			__entry->gen,
			__entry->flags & PAGEMAP_MAPPED		? "M" : " ",
			__entry->flags & PAGEMAP_ANONYMOUS	? "a" : "f",
			__entry->flags & PAGEMAP_SWAPCACHE	? "s" : " ",
			__entry->flags & PAGEMAP_SWAPBACKED	? "b" : " ",
			__entry->flags & PAGEMAP_MAPPEDDISK	? "d" : " ",
			__entry->flags & PAGEMAP_BUFFERS	? "B" : " ")
);

TRACE_EVENT(folio_update_gen,

	TP_PROTO(struct folio *folio, int newgen, int type),

	TP_ARGS(folio, newgen, type),

	TP_STRUCT__entry(
		__field(struct folio *,	folio	)
		__field(unsigned long,	pfn	)
		__field(int , type    )
		__field(int , oldgen    )
		__field(int , newgen    )
		__field(unsigned long,	flags	)
	),

	TP_fast_assign(
		__entry->folio	= folio;
		__entry->pfn	= folio_pfn(folio);
		__entry->oldgen	= ((READ_ONCE(folio->flags) & LRU_GEN_MASK) >> LRU_GEN_PGOFF) - 1;
		__entry->newgen	= newgen;
		__entry->type	= type;
		__entry->flags	= trace_pagemap_flags(folio);
	),

	/* Flag format is based on page-types.c formatting for pagemap */
	TP_printk("folio=%p[%s] pfn=0x%lx type:%s gen:%d->%d flags=%s%s%s%s%s%s",
			__entry->folio,
			folio_test_transhuge(__entry->folio)? "T": "N",
			__entry->pfn,
			__entry->type == 0 ? "other" : (__entry->type == 1 ? "norm" : "thp"),
			__entry->oldgen,
			__entry->newgen,
			__entry->flags & PAGEMAP_MAPPED		? "M" : " ",
			__entry->flags & PAGEMAP_ANONYMOUS	? "a" : "f",
			__entry->flags & PAGEMAP_SWAPCACHE	? "s" : " ",
			__entry->flags & PAGEMAP_SWAPBACKED	? "b" : " ",
			__entry->flags & PAGEMAP_MAPPEDDISK	? "d" : " ",
			__entry->flags & PAGEMAP_BUFFERS	? "B" : " ")
);

TRACE_EVENT(page_set_swapprio,

	TP_PROTO(struct page* page),

	TP_ARGS(page),

	TP_STRUCT__entry(
		__field(struct page* ,page)
	),

	TP_fast_assign(
		__entry->page	= page;
	),

	TP_printk("page@[%p] prio1[%d],prio2[%d]", 
                __entry->page,
                PageSwapPrio1(__entry->page),
                PageSwapPrio2(__entry->page))
);

#endif /* _TRACE_LRU_GEN_H */
#include <trace/define_trace.h>