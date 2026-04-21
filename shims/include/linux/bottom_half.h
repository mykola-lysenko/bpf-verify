/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: stub out bottom half / softirq operations */
#ifndef _LINUX_BH_H
#define _LINUX_BH_H

static inline void local_bh_disable(void) {}
static inline void local_bh_enable(void) {}
static inline void __local_bh_disable_ip(unsigned long ip, unsigned int cnt) {}
static inline void __local_bh_enable_ip(unsigned long ip, unsigned int cnt) {}
static inline void _local_bh_enable(void) {}

#define local_bh_disable()      do {} while (0)
#define local_bh_enable()       do {} while (0)

#endif /* _LINUX_BH_H */
