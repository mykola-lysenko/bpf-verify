/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CLEANUP_H
#define _LINUX_CLEANUP_H

/* Keep cleanup/guard syntax available, but model scope-exit operations as
 * no-ops for BPF verification. */
#define __cleanup(fn)

#define __bpf_cleanup_empty(...)
#define __bpf_cleanup_noop(...)		((void)0)
#define __bpf_cleanup_zero(...)		0
#define __bpf_cleanup_action(...)	__bpf_cleanup_noop
#define __bpf_cleanup_ptr(_scope)	((void *)(_scope))
#define __bpf_cleanup_get_and_null(p)			\
	({						\
		typeof(p) *__ptr = &(p);		\
		typeof(p) __val = *__ptr;		\
		*__ptr = (typeof(p))0;			\
		__val;					\
	})
#define __bpf_cleanup_scoped_once(_var)					\
	for (void *_var __attribute__((unused)) = (void *)1; _var;	\
	     _var = (void *)0)						\
		if (0) {						\
		} else

#define DEFINE_FREE			__bpf_cleanup_empty
#define __free				__bpf_cleanup_empty

#define no_free_ptr(p)		__bpf_cleanup_get_and_null(p)
#define return_ptr(p)		return no_free_ptr(p)
#define retain_and_null_ptr(p)	((void)no_free_ptr(p))

#define DEFINE_CLASS			__bpf_cleanup_empty
#define EXTEND_CLASS_COND		__bpf_cleanup_empty
#define EXTEND_CLASS			__bpf_cleanup_empty
#define CLASS				__bpf_cleanup_action
#define CLASS_INIT			__bpf_cleanup_empty
#define scoped_class(_name, _var, args...)	__bpf_cleanup_scoped_once(_var)

#define __DEFINE_CLASS_IS_CONDITIONAL	__bpf_cleanup_empty
#define DEFINE_CLASS_IS_UNCONDITIONAL	__bpf_cleanup_empty
#define DEFINE_CLASS_IS_GUARD		__bpf_cleanup_empty
#define DEFINE_CLASS_IS_COND_GUARD	__bpf_cleanup_empty
#define __guard_ptr(_name)	__bpf_cleanup_ptr
#define __guard_err(_name)	__bpf_cleanup_zero
#define __is_cond_ptr		__bpf_cleanup_zero

#define DEFINE_GUARD			__bpf_cleanup_empty
#define DEFINE_GUARD_COND_4		__bpf_cleanup_empty
#define DEFINE_GUARD_COND_3		__bpf_cleanup_empty
#define DEFINE_GUARD_COND		__bpf_cleanup_empty
#define guard				__bpf_cleanup_action

#define ACQUIRE			__bpf_cleanup_action
#define ACQUIRE_ERR		__bpf_cleanup_zero

#define scoped_guard(_name, args...)	__bpf_cleanup_scoped_once(scope)
#define scoped_cond_guard(_name, _fail, args...)	\
	scoped_guard(_name, args)

#define DEFINE_LOCK_GUARD_1		__bpf_cleanup_empty
#define DEFINE_LOCK_GUARD_0		__bpf_cleanup_empty
#define DEFINE_LOCK_GUARD_1_COND_4	__bpf_cleanup_empty
#define DEFINE_LOCK_GUARD_1_COND_3	__bpf_cleanup_empty
#define DEFINE_LOCK_GUARD_1_COND	__bpf_cleanup_empty

#define DECLARE_LOCK_GUARD_1_ATTRS	__bpf_cleanup_empty
#define DECLARE_LOCK_GUARD_0_ATTRS	__bpf_cleanup_empty
#define WITH_LOCK_GUARD_1_ATTRS(_name, _T)  (_T)

#endif /* _LINUX_CLEANUP_H */
