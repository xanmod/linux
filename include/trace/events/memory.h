/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM memory

#if !defined(__TRACE_MEMORY_H) || defined(TRACE_HEADER_MULTI_READ)
#define __TRACE_MEMORY_H

#include  <linux/tracepoint.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>

TRACE_EVENT(memory_handle_pte_fault,

	TP_PROTO(struct vm_fault *vmf, int place),

	TP_ARGS(vmf, place),

	TP_STRUCT__entry(
		__field(struct vm_fault *, vmf)
		__field(int, place)
	),

	TP_fast_assign(
		__entry->vmf = vmf;
		__entry->place = place;
	),

	TP_printk("vmf=%p,  place=%d",
		__entry->vmf,
		__entry->place)
);

#endif /* __TRACE_MEMORY_H */
#include <trace/define_trace.h>