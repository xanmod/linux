/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM thp

#if !defined(_TRACE_THP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_THP_H

#include <linux/types.h>
#include <linux/tracepoint.h>

TRACE_EVENT(hugepage_set_pmd,

	    TP_PROTO(unsigned long addr, unsigned long pmd),
	    TP_ARGS(addr, pmd),
	    TP_STRUCT__entry(
		    __field(unsigned long, addr)
		    __field(unsigned long, pmd)
		    ),

	    TP_fast_assign(
		    __entry->addr = addr;
		    __entry->pmd = pmd;
		    ),

	    TP_printk("Set pmd with 0x%lx with 0x%lx", __entry->addr, __entry->pmd)
);


TRACE_EVENT(hugepage_update,

	    TP_PROTO(unsigned long addr, unsigned long pte, unsigned long clr, unsigned long set),
	    TP_ARGS(addr, pte, clr, set),
	    TP_STRUCT__entry(
		    __field(unsigned long, addr)
		    __field(unsigned long, pte)
		    __field(unsigned long, clr)
		    __field(unsigned long, set)
		    ),

	    TP_fast_assign(
		    __entry->addr = addr;
		    __entry->pte = pte;
		    __entry->clr = clr;
		    __entry->set = set;

		    ),

	    TP_printk("hugepage update at addr 0x%lx and pte = 0x%lx clr = 0x%lx, set = 0x%lx", __entry->addr, __entry->pte, __entry->clr, __entry->set)
);

DECLARE_EVENT_CLASS(migration_pmd,

		TP_PROTO(unsigned long addr, unsigned long pmd),

		TP_ARGS(addr, pmd),

		TP_STRUCT__entry(
			__field(unsigned long, addr)
			__field(unsigned long, pmd)
		),

		TP_fast_assign(
			__entry->addr = addr;
			__entry->pmd = pmd;
		),
		TP_printk("addr=%lx, pmd=%lx", __entry->addr, __entry->pmd)
);

DEFINE_EVENT(migration_pmd, set_migration_pmd,
	TP_PROTO(unsigned long addr, unsigned long pmd),
	TP_ARGS(addr, pmd)
);

DEFINE_EVENT(migration_pmd, remove_migration_pmd,
	TP_PROTO(unsigned long addr, unsigned long pmd),
	TP_ARGS(addr, pmd)
);
/*DJL ADD BEGIN*/
TRACE_EVENT(add_thp_anon_rmap,

	    TP_PROTO(struct folio *folio,  struct vm_area_struct * vma,  unsigned long haddr, int count),
	    TP_ARGS(folio, vma, haddr, count),
	    TP_STRUCT__entry(
		    __field(struct folio *, folio)
		    __field(struct vm_area_struct *, vma)
		    __field(unsigned long , haddr)
			__field(int ,count)
		    ),

	    TP_fast_assign(
		    __entry->folio = folio;
		    __entry->vma = vma;
		    __entry->haddr = haddr;
			__entry->count = count;
		    ),

	    TP_printk("add_thp_anon_rmap thp[%p]  at vma %p addr 0x%lx folio_entire_mapcount:%d", 
				__entry->folio, __entry->vma, __entry->haddr, __entry->count)
);

TRACE_EVENT(hm_mapcount_dec,

		TP_PROTO(struct folio *folio, int count, bool file),
		TP_ARGS(folio, count, file),
		TP_STRUCT__entry(
		    __field(struct folio *, folio)
			__field(int ,count)
			__field(bool ,file)
		    ),
		
		TP_fast_assign(
		    __entry->folio = folio;
			__entry->count = count;
			__entry->file  = file;
		    ),
		TP_printk("[%s] thp[%p] folio_entire_mapcount:%d->%d", 
				__entry->file ? "FILE":"ANON", __entry->folio,  __entry->count, __entry->count-1)
);

TRACE_EVENT(hm_deferred_split,

		TP_PROTO(struct folio *folio, int count),
		TP_ARGS(folio, count),
		TP_STRUCT__entry(
		    __field(struct folio *, folio)
			__field(int ,count)
		    ),
		
		TP_fast_assign(
		    __entry->folio = folio;
			__entry->count = count;
		    ),
		TP_printk("thp[%p] folio_entire_mapcount:%d->%d", 
				 __entry->folio,  __entry->count, __entry->count-1)
);
/*DJL ADD END*/
#endif /* _TRACE_THP_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
