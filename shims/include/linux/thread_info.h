/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: linux/thread_info.h
 *
 * The real header pulls in asm/thread_info.h, which reaches x86 percpu and
 * CPU-feature headers with inline asm.  Keep only the common constants needed
 * by the BPF verification harnesses.
 */
#ifndef _LINUX_THREAD_INFO_H
#define _LINUX_THREAD_INFO_H

#include <linux/types.h>
#include <linux/bitops.h>

#define THREAD_ALIGN	THREAD_SIZE

#endif /* _LINUX_THREAD_INFO_H */
