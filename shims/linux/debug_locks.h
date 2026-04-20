/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: linux/debug_locks.h
 * The real debug_locks.h calls xchg() in __debug_locks_off() and returns int.
 * In BPF context, xchg() is a no-op (void), causing "returning non-void" errors.
 * Replace with BPF-safe stubs.
 */
#ifndef __LINUX_DEBUG_LOCKING_H
#define __LINUX_DEBUG_LOCKING_H

#include <linux/cache.h>

struct task_struct;

extern int debug_locks __read_mostly;
extern int debug_locks_silent __read_mostly;

static __always_inline int __debug_locks_off(void)
{
return 0;
}

static __always_inline int debug_locks_off(void)
{
return 0;
}

#define DEBUG_LOCKS_WARN_ON(c)({ (void)(c); 0; })
#define SMP_DEBUG_LOCKS_WARN_ON(c)do { } while (0)

#define locking_selftest()do { } while (0)

static inline void debug_show_all_locks(void) {}
static inline void debug_show_held_locks(struct task_struct *task) {}
static inline void debug_check_no_locks_freed(const void *from, unsigned long len) {}
static inline void debug_check_no_locks_held(void) {}

#endif /* __LINUX_DEBUG_LOCKING_H */
