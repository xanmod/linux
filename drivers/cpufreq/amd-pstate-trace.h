/* SPDX-License-Identifier: GPL-2.0 */
/*
 * amd-pstate-trace.h - AMD Processor P-state Frequency Driver Tracer
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Author: Huang Rui <ray.huang@amd.com>
 */

#if !defined(_AMD_PSTATE_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _AMD_PSTATE_TRACE_H

#include <linux/cpufreq.h>
#include <linux/tracepoint.h>
#include <linux/trace_events.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM amd_cpu

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE amd-pstate-trace

#define TPS(x)  tracepoint_string(x)

TRACE_EVENT(amd_pstate_perf,

	TP_PROTO(unsigned long min_perf,
		 unsigned long target_perf,
		 unsigned long capacity,
		 unsigned int cpu_id,
		 u64 prev,
		 u64 value,
		 int type
		 ),

	TP_ARGS(min_perf,
		target_perf,
		capacity,
		cpu_id,
		prev,
		value,
		type
		),

	TP_STRUCT__entry(
		__field(unsigned long, min_perf)
		__field(unsigned long, target_perf)
		__field(unsigned long, capacity)
		__field(unsigned int, cpu_id)
		__field(u64, prev)
		__field(u64, value)
		__field(int, type)
		),

	TP_fast_assign(
		__entry->min_perf = min_perf;
		__entry->target_perf = target_perf;
		__entry->capacity = capacity;
		__entry->cpu_id = cpu_id;
		__entry->prev = prev;
		__entry->value = value;
		__entry->type = type;
		),

	TP_printk("amd_min_perf=%lu amd_des_perf=%lu amd_max_perf=%lu cpu_id=%u prev=0x%llx value=0x%llx type=0x%d",
		  (unsigned long)__entry->min_perf,
		  (unsigned long)__entry->target_perf,
		  (unsigned long)__entry->capacity,
		  (unsigned int)__entry->cpu_id,
		  (u64)__entry->prev,
		  (u64)__entry->value,
		  (int)__entry->type
		 )
);

#endif /* _AMD_PSTATE_TRACE_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .

#include <trace/define_trace.h>
