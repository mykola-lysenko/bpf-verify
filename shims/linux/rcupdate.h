/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: stub out RCU - not needed for BPF verification */
#ifndef __LINUX_RCUPDATE_H
#define __LINUX_RCUPDATE_H

#include <linux/cleanup.h>

/* rcu_head is defined as callback_head in linux/types.h */
#define rcu_head callback_head

/* RCU read lock/unlock - no-ops */
#define rcu_read_lock()         do {} while (0)
#define rcu_read_unlock()       do {} while (0)
#define rcu_read_lock_bh()      do {} while (0)
#define rcu_read_unlock_bh()    do {} while (0)
#define rcu_read_lock_sched()   do {} while (0)
#define rcu_read_unlock_sched() do {} while (0)

/* RCU dereference/assign */
#define rcu_dereference(p)      READ_ONCE(p)
#define rcu_dereference_bh(p)   READ_ONCE(p)
#define rcu_dereference_sched(p) READ_ONCE(p)
#define rcu_dereference_raw(p)  READ_ONCE(p)
#define rcu_dereference_check(p, c) READ_ONCE(p)
#define rcu_dereference_protected(p, c) (p)
#define rcu_assign_pointer(p, v) WRITE_ONCE(p, v)

/* RCU callbacks */
#define call_rcu(head, func)    do {} while (0)
#define synchronize_rcu()       do {} while (0)
#define synchronize_rcu_expedited() do {} while (0)
#define synchronize_net()       do {} while (0)
#define rcu_barrier()           do {} while (0)

/* kfree_rcu */
#define kfree_rcu(ptr, field)   do {} while (0)
#define kfree_rcu_mightsleep(ptr) do {} while (0)

/* RCU init */
#define INIT_RCU_HEAD(ptr)      do {} while (0)
#define RCU_INIT_POINTER(p, v)  WRITE_ONCE(p, v)
#define RCU_POINTER_INITIALIZER(p, v) (v)

/* Guard integration */
DEFINE_LOCK_GUARD_0(rcu, rcu_read_lock(), rcu_read_unlock())

#endif /* __LINUX_RCUPDATE_H */
