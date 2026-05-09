/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CLEANUP_H
#define _LINUX_CLEANUP_H

/*
 * The real cleanup helpers rely on __attribute__((__cleanup__)) to run
 * destructors at scope exit.  For BPF verification shims we keep the source
 * syntax available, but model cleanup/guard operations as no-ops.
 */
#define __cleanup(fn)

#define __bpf_cleanup_noop(...)		((void)0)
#define __bpf_cleanup_ptr(_scope)	((void *)(_scope))
#define __bpf_cleanup_err(_scope)	0
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

#define DEFINE_FREE(_name, _type, _free)
#define __free(_freefn)

#define no_free_ptr(p)		__bpf_cleanup_get_and_null(p)
#define return_ptr(p)		return no_free_ptr(p)
#define retain_and_null_ptr(p)	((void)no_free_ptr(p))

#define DEFINE_CLASS(_name, _type, _exit, _init, _init_args...)
#define EXTEND_CLASS_COND(_name, _ext, _cond, _init, _init_args...)
#define EXTEND_CLASS(_name, _ext, _init, _init_args...)
#define CLASS(_name, var)		__bpf_cleanup_noop
#define CLASS_INIT(_name, _var, _init_expr)
#define scoped_class(_name, _var, args...)	__bpf_cleanup_scoped_once(_var)

#define __DEFINE_CLASS_IS_CONDITIONAL(_name, _is_cond)
#define DEFINE_CLASS_IS_UNCONDITIONAL(_name)
#define DEFINE_CLASS_IS_GUARD(_name)
#define DEFINE_CLASS_IS_COND_GUARD(_name)
#define __guard_ptr(_name)	__bpf_cleanup_ptr
#define __guard_err(_name)	__bpf_cleanup_err
#define __is_cond_ptr(_name)	0

#define DEFINE_GUARD(_name, _type, _lock, _unlock)
#define DEFINE_GUARD_COND_4(_name, _ext, _lock, _cond)
#define DEFINE_GUARD_COND_3(_name, _ext, _lock)
#define DEFINE_GUARD_COND(X...)
#define guard(_name)		__bpf_cleanup_noop

#define ACQUIRE(_name, _var)		__bpf_cleanup_noop
#define ACQUIRE_ERR(_name, _var)	0

#define scoped_guard(_name, args...)	__bpf_cleanup_scoped_once(scope)
#define scoped_cond_guard(_name, _fail, args...)	\
	__bpf_cleanup_scoped_once(scope)

#define DEFINE_LOCK_GUARD_1(_name, _type, _lock, _unlock, ...)
#define DEFINE_LOCK_GUARD_0(_name, _lock, _unlock, ...)
#define DEFINE_LOCK_GUARD_1_COND_4(_name, _ext, _lock, _cond)
#define DEFINE_LOCK_GUARD_1_COND_3(_name, _ext, _lock)
#define DEFINE_LOCK_GUARD_1_COND(X...)

#define DECLARE_LOCK_GUARD_1_ATTRS(_name, _lock, _unlock)
#define DECLARE_LOCK_GUARD_0_ATTRS(_name, _lock, _unlock)
#define WITH_LOCK_GUARD_1_ATTRS(_name, _T)  (_T)

#endif /* _LINUX_CLEANUP_H */
