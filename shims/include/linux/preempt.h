/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF shim: linux/preempt.h
 *
 * Keep the real preemption constants and helper macros. The asm/preempt.h shim
 * supplies BPF-safe preempt-count hooks, so most of the real header compiles to
 * barriers/no-ops. Preserve the previous shim's non-preemptible execution
 * model for code that checks preemptible().
 */
#ifndef __BPF_LINUX_PREEMPT_SHIM_H
#define __BPF_LINUX_PREEMPT_SHIM_H

#include_next <linux/preempt.h>

#undef preemptible
#define preemptible() 0

#endif /* __BPF_LINUX_PREEMPT_SHIM_H */
