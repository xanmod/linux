/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM vmscan

#if !defined(_TRACE_VMSCAN_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_VMSCAN_H

#include <linux/types.h>
#include <linux/tracepoint.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <trace/events/mmflags.h>

#define RECLAIM_WB_ANON		0x0001u
#define RECLAIM_WB_FILE		0x0002u
#define RECLAIM_WB_MIXED	0x0010u
#define RECLAIM_WB_SYNC		0x0004u /* Unused, all reclaim async */
#define RECLAIM_WB_ASYNC	0x0008u
#define RECLAIM_WB_LRU		(RECLAIM_WB_ANON|RECLAIM_WB_FILE)

#define show_reclaim_flags(flags)				\
	(flags) ? __print_flags(flags, "|",			\
		{RECLAIM_WB_ANON,	"RECLAIM_WB_ANON"},	\
		{RECLAIM_WB_FILE,	"RECLAIM_WB_FILE"},	\
		{RECLAIM_WB_MIXED,	"RECLAIM_WB_MIXED"},	\
		{RECLAIM_WB_SYNC,	"RECLAIM_WB_SYNC"},	\
		{RECLAIM_WB_ASYNC,	"RECLAIM_WB_ASYNC"}	\
		) : "RECLAIM_WB_NONE"

#define _VMSCAN_THROTTLE_WRITEBACK	(1 << VMSCAN_THROTTLE_WRITEBACK)
#define _VMSCAN_THROTTLE_ISOLATED	(1 << VMSCAN_THROTTLE_ISOLATED)
#define _VMSCAN_THROTTLE_NOPROGRESS	(1 << VMSCAN_THROTTLE_NOPROGRESS)
#define _VMSCAN_THROTTLE_CONGESTED	(1 << VMSCAN_THROTTLE_CONGESTED)

#define show_throttle_flags(flags)						\
	(flags) ? __print_flags(flags, "|",					\
		{_VMSCAN_THROTTLE_WRITEBACK,	"VMSCAN_THROTTLE_WRITEBACK"},	\
		{_VMSCAN_THROTTLE_ISOLATED,	"VMSCAN_THROTTLE_ISOLATED"},	\
		{_VMSCAN_THROTTLE_NOPROGRESS,	"VMSCAN_THROTTLE_NOPROGRESS"},	\
		{_VMSCAN_THROTTLE_CONGESTED,	"VMSCAN_THROTTLE_CONGESTED"}	\
		) : "VMSCAN_THROTTLE_NONE"


#define trace_reclaim_flags(file) ( \
	(file ? RECLAIM_WB_FILE : RECLAIM_WB_ANON) | \
	(RECLAIM_WB_ASYNC) \
	)

TRACE_EVENT(mm_vmscan_kswapd_sleep,

	TP_PROTO(int nid),

	TP_ARGS(nid),

	TP_STRUCT__entry(
		__field(	int,	nid	)
	),

	TP_fast_assign(
		__entry->nid	= nid;
	),

	TP_printk("nid=%d", __entry->nid)
);

TRACE_EVENT(mm_vmscan_kswapd_wake,

	TP_PROTO(int nid, int zid, int order),

	TP_ARGS(nid, zid, order),

	TP_STRUCT__entry(
		__field(	int,	nid	)
		__field(	int,	zid	)
		__field(	int,	order	)
	),

	TP_fast_assign(
		__entry->nid	= nid;
		__entry->zid    = zid;
		__entry->order	= order;
	),

	TP_printk("nid=%d order=%d",
		__entry->nid,
		__entry->order)
);

TRACE_EVENT(mm_vmscan_wakeup_kswapd,

	TP_PROTO(int nid, int zid, int order, gfp_t gfp_flags, int place),

	TP_ARGS(nid, zid, order, gfp_flags, place),

	TP_STRUCT__entry(
		__field(	int,	nid		)
		__field(	int,	zid		)
		__field(	int,	order		)
		__field(	unsigned long,	gfp_flags	)
		__field(	int,	place		)
	),

	TP_fast_assign(
		__entry->nid		= nid;
		__entry->zid		= zid;
		__entry->order		= order;
		__entry->gfp_flags	= (__force unsigned long)gfp_flags;
		__entry->place		= place;
	),

	TP_printk("[%d] nid=%d zid=%d order=%d gfp_flags=%s",
		__entry->place,
		__entry->nid,
		__entry->zid,
		__entry->order,
		show_gfp_flags(__entry->gfp_flags))
);

DECLARE_EVENT_CLASS(mm_vmscan_direct_reclaim_begin_template,

	TP_PROTO(int order, gfp_t gfp_flags),

	TP_ARGS(order, gfp_flags),

	TP_STRUCT__entry(
		__field(	int,	order		)
		__field(	unsigned long,	gfp_flags	)
	),

	TP_fast_assign(
		__entry->order		= order;
		__entry->gfp_flags	= (__force unsigned long)gfp_flags;
	),

	TP_printk("order=%d gfp_flags=%s",
		__entry->order,
		show_gfp_flags(__entry->gfp_flags))
);

DEFINE_EVENT(mm_vmscan_direct_reclaim_begin_template, mm_vmscan_direct_reclaim_begin,

	TP_PROTO(int order, gfp_t gfp_flags),

	TP_ARGS(order, gfp_flags)
);

#ifdef CONFIG_MEMCG
DEFINE_EVENT(mm_vmscan_direct_reclaim_begin_template, mm_vmscan_memcg_reclaim_begin,

	TP_PROTO(int order, gfp_t gfp_flags),

	TP_ARGS(order, gfp_flags)
);

DEFINE_EVENT(mm_vmscan_direct_reclaim_begin_template, mm_vmscan_memcg_softlimit_reclaim_begin,

	TP_PROTO(int order, gfp_t gfp_flags),

	TP_ARGS(order, gfp_flags)
);
#endif /* CONFIG_MEMCG */

DECLARE_EVENT_CLASS(mm_vmscan_direct_reclaim_end_template,

	TP_PROTO(unsigned long nr_reclaimed),

	TP_ARGS(nr_reclaimed),

	TP_STRUCT__entry(
		__field(	unsigned long,	nr_reclaimed	)
	),

	TP_fast_assign(
		__entry->nr_reclaimed	= nr_reclaimed;
	),

	TP_printk("nr_reclaimed=%lu", __entry->nr_reclaimed)
);

DEFINE_EVENT(mm_vmscan_direct_reclaim_end_template, mm_vmscan_direct_reclaim_end,

	TP_PROTO(unsigned long nr_reclaimed),

	TP_ARGS(nr_reclaimed)
);

#ifdef CONFIG_MEMCG
DEFINE_EVENT(mm_vmscan_direct_reclaim_end_template, mm_vmscan_memcg_reclaim_end,

	TP_PROTO(unsigned long nr_reclaimed),

	TP_ARGS(nr_reclaimed)
);

DEFINE_EVENT(mm_vmscan_direct_reclaim_end_template, mm_vmscan_memcg_softlimit_reclaim_end,

	TP_PROTO(unsigned long nr_reclaimed),

	TP_ARGS(nr_reclaimed)
);
#endif /* CONFIG_MEMCG */
/*DJL ADD BEGIN*/
struct scan_control;
TRACE_EVENT(mm_mglru_evict_folios_start,
	TP_PROTO(struct lruvec *lruvec, struct scan_control* sc, 
			unsigned long scanned , int delta, int swappiness, 
			bool need_swapping, bool need_aging),
	
	TP_ARGS(lruvec, sc, scanned, delta, swappiness, need_swapping,
			need_aging),

	TP_STRUCT__entry(
		__field(struct lruvec *, lruvec 	)
		__field(struct scan_control* , sc	)
		__field(unsigned long , scanned	)
		__field(int , delta	)
		__field(int ,swappiness	)
		__field(bool , need_swapping	)
		__field(bool , need_aging	)
	),

	TP_fast_assign(
		__entry->lruvec 	= lruvec;
		__entry->sc			= sc;
		__entry->scanned	= scanned;
		__entry->delta		= delta;
		__entry->swappiness = swappiness;
		__entry->need_swapping = need_swapping;
		__entry->need_aging	= need_aging;
	),

	TP_printk("lruvec[%p] sc[%p] scanned:%ld delta:%d swappiness:%d need_swapping:%s need_aging:%s",
		__entry->lruvec,
		__entry->sc,
		__entry->scanned,
		__entry->delta,
		__entry->swappiness,
		__entry->need_swapping ? "T" : "F",
		__entry->need_aging	   ? "T" : "F")
);
TRACE_EVENT(mm_mglru_evict_folios_end,
	TP_PROTO(struct lruvec *lruvec, struct scan_control* sc, 
			unsigned long scanned , int delta, int swappiness, 
			bool need_swapping, bool need_aging),
	
	TP_ARGS(lruvec, sc, scanned, delta, swappiness, need_swapping,
			need_aging),

	TP_STRUCT__entry(
		__field(struct lruvec *, lruvec 	)
		__field(struct scan_control* , sc	)
		__field(unsigned long , scanned	)
		__field(int , delta	)
		__field(int ,swappiness	)
		__field(bool , need_swapping	)
		__field(bool , need_aging	)
	),

	TP_fast_assign(
		__entry->lruvec 	= lruvec;
		__entry->sc			= sc;
		__entry->scanned	= scanned;
		__entry->delta		= delta;
		__entry->swappiness = swappiness;
		__entry->need_swapping = need_swapping;
		__entry->need_aging	= need_aging;
	),

	TP_printk("lruvec[%p] sc[%p] scanned:%ld delta:%d swappiness:%d need_swapping:%s need_aging:%s",
		__entry->lruvec,
		__entry->sc,
		__entry->scanned,
		__entry->delta,
		__entry->swappiness,
		__entry->need_swapping ? "T" : "F",
		__entry->need_aging    ? "T" : "F")
);
/*DJL ADD END*/
TRACE_EVENT(mm_shrink_slab_start,
	TP_PROTO(struct shrinker *shr, struct shrink_control *sc,
		long nr_objects_to_shrink, unsigned long cache_items,
		unsigned long long delta, unsigned long total_scan,
		int priority),

	TP_ARGS(shr, sc, nr_objects_to_shrink, cache_items, delta, total_scan,
		priority),

	TP_STRUCT__entry(
		__field(struct shrinker *, shr)
		__field(void *, shrink)
		__field(int, nid)
		__field(long, nr_objects_to_shrink)
		__field(unsigned long, gfp_flags)
		__field(unsigned long, cache_items)
		__field(unsigned long long, delta)
		__field(unsigned long, total_scan)
		__field(int, priority)
	),

	TP_fast_assign(
		__entry->shr = shr;
		__entry->shrink = shr->scan_objects;
		__entry->nid = sc->nid;
		__entry->nr_objects_to_shrink = nr_objects_to_shrink;
		__entry->gfp_flags = (__force unsigned long)sc->gfp_mask;
		__entry->cache_items = cache_items;
		__entry->delta = delta;
		__entry->total_scan = total_scan;
		__entry->priority = priority;
	),

	TP_printk("%pS %p: nid: %d objects to shrink %ld gfp_flags %s cache items %ld delta %lld total_scan %ld priority %d",
		__entry->shrink,
		__entry->shr,
		__entry->nid,
		__entry->nr_objects_to_shrink,
		show_gfp_flags(__entry->gfp_flags),
		__entry->cache_items,
		__entry->delta,
		__entry->total_scan,
		__entry->priority)
);

TRACE_EVENT(mm_shrink_slab_end,
	TP_PROTO(struct shrinker *shr, int nid, int shrinker_retval,
		long unused_scan_cnt, long new_scan_cnt, long total_scan),

	TP_ARGS(shr, nid, shrinker_retval, unused_scan_cnt, new_scan_cnt,
		total_scan),

	TP_STRUCT__entry(
		__field(struct shrinker *, shr)
		__field(int, nid)
		__field(void *, shrink)
		__field(long, unused_scan)
		__field(long, new_scan)
		__field(int, retval)
		__field(long, total_scan)
	),

	TP_fast_assign(
		__entry->shr = shr;
		__entry->nid = nid;
		__entry->shrink = shr->scan_objects;
		__entry->unused_scan = unused_scan_cnt;
		__entry->new_scan = new_scan_cnt;
		__entry->retval = shrinker_retval;
		__entry->total_scan = total_scan;
	),

	TP_printk("%pS %p: nid: %d unused scan count %ld new scan count %ld total_scan %ld last shrinker return val %d",
		__entry->shrink,
		__entry->shr,
		__entry->nid,
		__entry->unused_scan,
		__entry->new_scan,
		__entry->total_scan,
		__entry->retval)
);

TRACE_EVENT(mm_vmscan_lru_isolate,
	TP_PROTO(int highest_zoneidx,
		int order,
		unsigned long nr_requested,
		unsigned long nr_scanned,
		unsigned long nr_skipped,
		unsigned long nr_taken,
		isolate_mode_t isolate_mode,
		int lru),

	TP_ARGS(highest_zoneidx, order, nr_requested, nr_scanned, nr_skipped, nr_taken, isolate_mode, lru),

	TP_STRUCT__entry(
		__field(int, highest_zoneidx)
		__field(int, order)
		__field(unsigned long, nr_requested)
		__field(unsigned long, nr_scanned)
		__field(unsigned long, nr_skipped)
		__field(unsigned long, nr_taken)
		__field(unsigned int, isolate_mode)
		__field(int, lru)
	),

	TP_fast_assign(
		__entry->highest_zoneidx = highest_zoneidx;
		__entry->order = order;
		__entry->nr_requested = nr_requested;
		__entry->nr_scanned = nr_scanned;
		__entry->nr_skipped = nr_skipped;
		__entry->nr_taken = nr_taken;
		__entry->isolate_mode = (__force unsigned int)isolate_mode;
		__entry->lru = lru;
	),

	/*
	 * classzone is previous name of the highest_zoneidx.
	 * Reason not to change it is the ABI requirement of the tracepoint.
	 */
	TP_printk("isolate_mode=%d classzone=%d order=%d nr_requested=%lu nr_scanned=%lu nr_skipped=%lu nr_taken=%lu lru=%s",
		__entry->isolate_mode,
		__entry->highest_zoneidx,
		__entry->order,
		__entry->nr_requested,
		__entry->nr_scanned,
		__entry->nr_skipped,
		__entry->nr_taken,
		__print_symbolic(__entry->lru, LRU_NAMES))
);

TRACE_EVENT(mm_vmscan_write_folio,

	TP_PROTO(struct folio *folio),

	TP_ARGS(folio),

	TP_STRUCT__entry(
		__field(unsigned long, pfn)
		__field(int, reclaim_flags)
	),

	TP_fast_assign(
		__entry->pfn = folio_pfn(folio);
		__entry->reclaim_flags = trace_reclaim_flags(
						folio_is_file_lru(folio));
	),

	TP_printk("page=%p pfn=0x%lx flags=%s",
		pfn_to_page(__entry->pfn),
		__entry->pfn,
		show_reclaim_flags(__entry->reclaim_flags))
);

TRACE_EVENT(mm_vmscan_lru_shrink_inactive,

	TP_PROTO(int nid,
		unsigned long nr_scanned, unsigned long nr_reclaimed,
		struct reclaim_stat *stat, int priority, int file),

	TP_ARGS(nid, nr_scanned, nr_reclaimed, stat, priority, file),

	TP_STRUCT__entry(
		__field(int, nid)
		__field(unsigned long, nr_scanned)
		__field(unsigned long, nr_reclaimed)
		__field(unsigned long, nr_dirty)
		__field(unsigned long, nr_writeback)
		__field(unsigned long, nr_congested)
		__field(unsigned long, nr_immediate)
		__field(unsigned int, nr_activate0)
		__field(unsigned int, nr_activate1)
		__field(unsigned long, nr_ref_keep)
		__field(unsigned long, nr_unmap_fail)
		__field(int, priority)
		__field(int, reclaim_flags)
	),

	TP_fast_assign(
		__entry->nid = nid;
		__entry->nr_scanned = nr_scanned;
		__entry->nr_reclaimed = nr_reclaimed;
		__entry->nr_dirty = stat->nr_dirty;
		__entry->nr_writeback = stat->nr_writeback;
		__entry->nr_congested = stat->nr_congested;
		__entry->nr_immediate = stat->nr_immediate;
		__entry->nr_activate0 = stat->nr_activate[0];
		__entry->nr_activate1 = stat->nr_activate[1];
		__entry->nr_ref_keep = stat->nr_ref_keep;
		__entry->nr_unmap_fail = stat->nr_unmap_fail;
		__entry->priority = priority;
		__entry->reclaim_flags = trace_reclaim_flags(file);
	),

	TP_printk("nid=%d nr_scanned=%ld nr_reclaimed=%ld nr_dirty=%ld nr_writeback=%ld nr_congested=%ld nr_immediate=%ld nr_activate_anon=%d nr_activate_file=%d nr_ref_keep=%ld nr_unmap_fail=%ld priority=%d flags=%s",
		__entry->nid,
		__entry->nr_scanned, __entry->nr_reclaimed,
		__entry->nr_dirty, __entry->nr_writeback,
		__entry->nr_congested, __entry->nr_immediate,
		__entry->nr_activate0, __entry->nr_activate1,
		__entry->nr_ref_keep, __entry->nr_unmap_fail,
		__entry->priority,
		show_reclaim_flags(__entry->reclaim_flags))
);

TRACE_EVENT(mm_vmscan_lru_shrink_active,

	TP_PROTO(int nid, unsigned long nr_taken,
		unsigned long nr_active, unsigned long nr_deactivated,
		unsigned long nr_referenced, int priority, int file),

	TP_ARGS(nid, nr_taken, nr_active, nr_deactivated, nr_referenced, priority, file),

	TP_STRUCT__entry(
		__field(int, nid)
		__field(unsigned long, nr_taken)
		__field(unsigned long, nr_active)
		__field(unsigned long, nr_deactivated)
		__field(unsigned long, nr_referenced)
		__field(int, priority)
		__field(int, reclaim_flags)
	),

	TP_fast_assign(
		__entry->nid = nid;
		__entry->nr_taken = nr_taken;
		__entry->nr_active = nr_active;
		__entry->nr_deactivated = nr_deactivated;
		__entry->nr_referenced = nr_referenced;
		__entry->priority = priority;
		__entry->reclaim_flags = trace_reclaim_flags(file);
	),

	TP_printk("nid=%d nr_taken=%ld nr_active=%ld nr_deactivated=%ld nr_referenced=%ld priority=%d flags=%s",
		__entry->nid,
		__entry->nr_taken,
		__entry->nr_active, __entry->nr_deactivated, __entry->nr_referenced,
		__entry->priority,
		show_reclaim_flags(__entry->reclaim_flags))
);

TRACE_EVENT(mm_vmscan_node_reclaim_begin,

	TP_PROTO(int nid, int order, gfp_t gfp_flags),

	TP_ARGS(nid, order, gfp_flags),

	TP_STRUCT__entry(
		__field(int, nid)
		__field(int, order)
		__field(unsigned long, gfp_flags)
	),

	TP_fast_assign(
		__entry->nid = nid;
		__entry->order = order;
		__entry->gfp_flags = (__force unsigned long)gfp_flags;
	),

	TP_printk("nid=%d order=%d gfp_flags=%s",
		__entry->nid,
		__entry->order,
		show_gfp_flags(__entry->gfp_flags))
);

DEFINE_EVENT(mm_vmscan_direct_reclaim_end_template, mm_vmscan_node_reclaim_end,

	TP_PROTO(unsigned long nr_reclaimed),

	TP_ARGS(nr_reclaimed)
);

TRACE_EVENT(mm_vmscan_throttled,

	TP_PROTO(int nid, int usec_timeout, int usec_delayed, int reason),

	TP_ARGS(nid, usec_timeout, usec_delayed, reason),

	TP_STRUCT__entry(
		__field(int, nid)
		__field(int, usec_timeout)
		__field(int, usec_delayed)
		__field(int, reason)
	),

	TP_fast_assign(
		__entry->nid = nid;
		__entry->usec_timeout = usec_timeout;
		__entry->usec_delayed = usec_delayed;
		__entry->reason = 1U << reason;
	),

	TP_printk("nid=%d usec_timeout=%d usect_delayed=%d reason=%s",
		__entry->nid,
		__entry->usec_timeout,
		__entry->usec_delayed,
		show_throttle_flags(__entry->reason))
);
TRACE_EVENT(mm_ano_folio2,

	TP_PROTO(struct folio *folio, int count, bool test),

	TP_ARGS(folio, count, test),

	TP_STRUCT__entry(
		__field(struct folio* ,folio)
		__field(int, reclaim_flags)
		__field(int, count)
		__field(bool, test)
	),

	TP_fast_assign(
		__entry->folio = folio;
		__entry->reclaim_flags = trace_reclaim_flags(
						folio_is_file_lru(folio));
		__entry->count = count;
		__entry->test = test;
	),

	TP_printk("folio=%p  [%s][%s][mapcount=%d][%d] flags=%s",
		__entry->folio, 
		folio_test_swapbacked(__entry->folio) ? "swp_bk":"no_swap_bk" ,
		folio_test_swapcache(__entry->folio) ? "swp_$" : "no_swp_$", 
		__entry->count,
		__entry->test,
		show_reclaim_flags(__entry->reclaim_flags))
);
TRACE_EVENT(mm_ano_folio,

	TP_PROTO(struct folio *folio, int gen),

	TP_ARGS(folio, gen),

	TP_STRUCT__entry(
		__field(struct folio* ,folio)
		__field(int, reclaim_flags)
		__field(int, gen)
	),

	TP_fast_assign(
		__entry->folio = folio;
		__entry->reclaim_flags = trace_reclaim_flags(
						folio_is_file_lru(folio));
		__entry->gen = gen;
	),

	TP_printk("folio=%p  [gen:%d][%s][%s] flags=%s",
		__entry->folio, 
		__entry->gen,
		folio_test_swapbacked(__entry->folio) ? "swp_bk":"no_swap_bk" ,
		folio_test_swapcache(__entry->folio) ? "swp_$" : "no_swp_$", 
		show_reclaim_flags(__entry->reclaim_flags))
);

TRACE_EVENT(mm_isolate_folios,

	TP_PROTO(struct lruvec *lruvec, int type),

	TP_ARGS(lruvec, type),

	TP_STRUCT__entry(
		__field(struct lruvec *, lruvec)
		__field(int, type)
	),

	TP_fast_assign(
		__entry->lruvec = lruvec;
		__entry->type = type;
	),

	TP_printk("lruvec=%p type=%s ",
		__entry->lruvec, 
		__entry->type == 0 ? "LRU_GEN_ANON" : "LRU_GEN_FILE")
);

TRACE_EVENT(try_charge_memcg,

	TP_PROTO(struct mem_cgroup * memcg, struct page_counter * memsw, int nr_pages, int type),

	TP_ARGS(memcg, memsw, nr_pages, type),

	TP_STRUCT__entry(
		__field(struct mem_cgroup * ,memcg)
		__field(struct page_counter * ,memsw)
		__field(int, nr_pages)
		__field(int, type)
	),

	TP_fast_assign(
		__entry->memcg = memcg;
		__entry->memsw = memsw;
		__entry->nr_pages = nr_pages;
		__entry->type = type;
	),

	TP_printk("memcg=%p nrpages:%d usage:%ld max:%ld watermark:%ld %s ",
		__entry->memcg, 
		__entry->nr_pages,
		atomic_long_read(&__entry->memsw->usage),
		READ_ONCE(__entry->memsw->max),
		READ_ONCE(__entry->memsw->watermark),
		__entry->type == 0 ? "[from batch]" : "[from memsw]")
);
#endif /* _TRACE_VMSCAN_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
