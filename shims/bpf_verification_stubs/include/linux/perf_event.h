/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PERF_EVENT_H
#define _LINUX_PERF_EVENT_H

#include <linux/types.h>

#define PERF_MAX_STACK_DEPTH	127

struct pt_regs {
	unsigned long ip;
};

struct perf_callchain_entry {
	u32 nr;
	u64 ip[8];
};

#endif /* _LINUX_PERF_EVENT_H */
