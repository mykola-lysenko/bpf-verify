/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: model RCU as plain loads/stores and no-op grace periods. */
#ifndef __LINUX_RCUPDATE_H
#define __LINUX_RCUPDATE_H

#include <linux/compiler.h>
#include <linux/cleanup.h>
#include <linux/types.h>

#ifndef rcu_head
#define rcu_head callback_head
#endif

#define __bpf_rcu_noop(...)		do { } while (0)
#define __bpf_rcu_read(p)		READ_ONCE(p)

/* RCU read lock/unlock - no-ops */
#define rcu_read_lock()			__bpf_rcu_noop()
#define rcu_read_unlock()		__bpf_rcu_noop()
#define rcu_read_lock_bh()		__bpf_rcu_noop()
#define rcu_read_unlock_bh()		__bpf_rcu_noop()
#define rcu_read_lock_sched()		__bpf_rcu_noop()
#define rcu_read_unlock_sched()		__bpf_rcu_noop()
#define rcu_preempt_depth()		0

/* RCU dereference/assign */
#define rcu_dereference(p)		__bpf_rcu_read(p)
#define rcu_dereference_bh(p)		__bpf_rcu_read(p)
#define rcu_dereference_sched(p)	__bpf_rcu_read(p)
#define rcu_dereference_raw(p)		__bpf_rcu_read(p)
#define rcu_dereference_check(p, c)	__bpf_rcu_read(p)
#define rcu_dereference_bh_check(p, c)	__bpf_rcu_read(p)
#define rcu_dereference_sched_check(p, c) __bpf_rcu_read(p)
#define rcu_dereference_all_check(p, c)	__bpf_rcu_read(p)
#define rcu_dereference_raw_check(p)	__bpf_rcu_read(p)
#define rcu_dereference_all(p)		__bpf_rcu_read(p)
#define rcu_dereference_protected(p, c)	(p)
#define rcu_access_pointer(p)		__bpf_rcu_read(p)
#define rcu_pointer_handoff(p)		(p)
#define rcu_assign_pointer(p, v)	WRITE_ONCE(p, v)
#define rcu_replace_pointer(rcu_ptr, ptr, c)			\
({								\
	typeof(ptr) __tmp = rcu_dereference_protected((rcu_ptr), (c)); \
	rcu_assign_pointer((rcu_ptr), (ptr));			\
	__tmp;							\
})

/* RCU callbacks */
static inline void call_rcu(struct rcu_head *head, rcu_callback_t func)
{
	(void)head;
	(void)func;
}

static inline void call_rcu_hurry(struct rcu_head *head, rcu_callback_t func)
{
	call_rcu(head, func);
}

static inline void call_rcu_tasks(struct rcu_head *head, rcu_callback_t func)
{
	call_rcu(head, func);
}

static inline void synchronize_rcu(void) { }
static inline void synchronize_rcu_expedited(void) { }
static inline void synchronize_rcu_tasks(void) { }
static inline void synchronize_rcu_tasks_rude(void) { }
static inline void synchronize_net(void) { }
static inline void rcu_barrier(void) { }
static inline void rcu_barrier_tasks(void) { }

#define rcu_tasks_classic_qs(t, preempt)	__bpf_rcu_noop(t, preempt)
#define rcu_tasks_qs(t, preempt)		__bpf_rcu_noop(t, preempt)
#define rcu_note_voluntary_context_switch(t)	__bpf_rcu_noop(t)
#define cond_resched_tasks_rcu_qs()		__bpf_rcu_noop()

/* kfree_rcu */
#define kfree_rcu(ptr, field)		__bpf_rcu_noop(ptr, field)
#define kvfree_rcu(ptr, field)		__bpf_rcu_noop(ptr, field)
#define kfree_rcu_mightsleep(ptr)	__bpf_rcu_noop(ptr)
#define kvfree_rcu_mightsleep(ptr)	__bpf_rcu_noop(ptr)

/* RCU init */
#define INIT_RCU_HEAD(ptr)		__bpf_rcu_noop(ptr)
#define RCU_INITIALIZER(v)		(v)
#define RCU_INIT_POINTER(p, v)		WRITE_ONCE(p, RCU_INITIALIZER(v))
#define RCU_POINTER_INITIALIZER(p, v)	.p = RCU_INITIALIZER(v)

static inline void init_rcu_head(struct rcu_head *head) { (void)head; }
static inline void destroy_rcu_head(struct rcu_head *head) { (void)head; }
static inline void init_rcu_head_on_stack(struct rcu_head *head) { (void)head; }
static inline void destroy_rcu_head_on_stack(struct rcu_head *head) { (void)head; }

/* Lock debugging / lockdep stubs */
static inline int rcu_read_lock_held(void) { return 1; }
static inline int rcu_read_lock_bh_held(void) { return 1; }
static inline int rcu_read_lock_sched_held(void) { return 1; }
static inline int rcu_read_lock_any_held(void) { return 1; }
static inline int rcu_is_watching(void) { return 1; }
static inline void rcu_try_lock_acquire(void *m) { (void)m; }
static inline void rcu_try_lock_release(void *m) { (void)m; }

/* RCU lockdep warn stub */
#define RCU_LOCKDEP_WARN(c, s)		__bpf_rcu_noop(c, s)
#define RCU_NOCB_LOCKDEP_WARN(c, s)	__bpf_rcu_noop(c, s)
#define rcu_sleep_check()		__bpf_rcu_noop()
#define lockdep_assert_in_rcu_read_lock()	__bpf_rcu_noop()
#define lockdep_assert_in_rcu_read_lock_bh()	__bpf_rcu_noop()
#define lockdep_assert_in_rcu_read_lock_sched()	__bpf_rcu_noop()
#define lockdep_assert_in_rcu_reader()		__bpf_rcu_noop()

#endif /* __LINUX_RCUPDATE_H */
