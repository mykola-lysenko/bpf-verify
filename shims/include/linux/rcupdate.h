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

#define __bpf_rcu_noop()		do { } while (0)
#define __bpf_rcu_noop1(arg)		do { (void)(arg); } while (0)
#define __bpf_rcu_noop2(arg1, arg2)	do { (void)(arg1); (void)(arg2); } while (0)
#define __bpf_rcu_read(p)		READ_ONCE(p)

#define __bpf_kvfree_rcu_arg_2(ptr, rhf)		\
do {							\
	typeof(ptr) __ptr = (ptr);			\
	(void)__ptr;					\
} while (0)

#define __bpf_kvfree_rcu_arg_1(ptr)			\
do {							\
	typeof(ptr) __ptr = (ptr);			\
	(void)__ptr;					\
} while (0)

/* RCU read lock/unlock - no-ops */
#define rcu_read_lock()			__bpf_rcu_noop()
#define rcu_read_unlock		rcu_read_lock
#define rcu_read_lock_bh		rcu_read_lock
#define rcu_read_unlock_bh		rcu_read_lock
#define rcu_read_lock_sched		rcu_read_lock
#define rcu_read_unlock_sched		rcu_read_lock
#define rcu_preempt_depth()		0

/* RCU dereference/assign */
#define rcu_dereference(p)		__bpf_rcu_read(p)
#define rcu_dereference_bh		rcu_dereference
#define rcu_dereference_sched		rcu_dereference
#define rcu_dereference_raw		rcu_dereference
#define rcu_dereference_check(p, c)	__bpf_rcu_read(p)
#define rcu_dereference_bh_check	rcu_dereference_check
#define rcu_dereference_sched_check	rcu_dereference_check
#define rcu_dereference_all_check	rcu_dereference_check
#define rcu_dereference_raw_check(p)	__bpf_rcu_read(p)
#define rcu_dereference_all		rcu_dereference
#define rcu_dereference_protected(p, c)	(p)
#define rcu_access_pointer		rcu_dereference
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

#define call_rcu_hurry		call_rcu
#define call_rcu_tasks		call_rcu

#define synchronize_rcu()		__bpf_rcu_noop()
#define synchronize_rcu_expedited	synchronize_rcu
#define synchronize_rcu_tasks		synchronize_rcu
#define synchronize_rcu_tasks_rude	synchronize_rcu
#define synchronize_net			synchronize_rcu
#define rcu_barrier			synchronize_rcu
#define rcu_barrier_tasks		synchronize_rcu

#define rcu_tasks_classic_qs(t, preempt)	__bpf_rcu_noop2(t, preempt)
#define rcu_tasks_qs			rcu_tasks_classic_qs
#define rcu_note_voluntary_context_switch(t)	__bpf_rcu_noop1(t)
#define cond_resched_tasks_rcu_qs()		__bpf_rcu_noop()

/* kfree_rcu */
#define kfree_rcu(ptr, rhf)		__bpf_kvfree_rcu_arg_2(ptr, rhf)
#define kvfree_rcu(ptr, rhf)		__bpf_kvfree_rcu_arg_2(ptr, rhf)
#define kfree_rcu_mightsleep(ptr)	__bpf_kvfree_rcu_arg_1(ptr)
#define kvfree_rcu_mightsleep(ptr)	__bpf_kvfree_rcu_arg_1(ptr)

/* RCU init */
static inline void init_rcu_head(struct rcu_head *head)
{
	(void)head;
}

static inline void destroy_rcu_head(struct rcu_head *head)
{
	(void)head;
}

static inline void init_rcu_head_on_stack(struct rcu_head *head)
{
	(void)head;
}

static inline void destroy_rcu_head_on_stack(struct rcu_head *head)
{
	(void)head;
}

#define INIT_RCU_HEAD(ptr)		init_rcu_head(ptr)
#define RCU_INITIALIZER(v)		(v)
#define RCU_INIT_POINTER(p, v)		WRITE_ONCE(p, RCU_INITIALIZER(v))
#define RCU_POINTER_INITIALIZER(p, v)	.p = RCU_INITIALIZER(v)

/* Lock debugging / lockdep stubs */
#define rcu_read_lock_held()		1
#define rcu_read_lock_bh_held		rcu_read_lock_held
#define rcu_read_lock_sched_held	rcu_read_lock_held
#define rcu_read_lock_any_held		rcu_read_lock_held
#define rcu_is_watching		rcu_read_lock_held
#define rcu_try_lock_acquire(map)	__bpf_rcu_noop1(map)
#define rcu_try_lock_release(map)	__bpf_rcu_noop1(map)

/* RCU lockdep warn stub */
#define RCU_LOCKDEP_WARN(c, s)		do { } while (0 && (c))
#define RCU_NOCB_LOCKDEP_WARN		RCU_LOCKDEP_WARN
#define rcu_sleep_check()		__bpf_rcu_noop()
#define lockdep_assert_in_rcu_read_lock		rcu_sleep_check
#define lockdep_assert_in_rcu_read_lock_bh	rcu_sleep_check
#define lockdep_assert_in_rcu_read_lock_sched	rcu_sleep_check
#define lockdep_assert_in_rcu_reader		rcu_sleep_check

#endif /* __LINUX_RCUPDATE_H */
