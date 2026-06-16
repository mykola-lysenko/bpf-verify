/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CLEANUP_H
#define _LINUX_CLEANUP_H

/* Keep cleanup/guard syntax available, but model scope-exit operations as
 * no-ops for BPF verification.  Avoid including compiler.h/args.h here: this
 * shim is often pulled in by low-level headers while those dependencies are
 * still being modeled.
 */
#undef __cleanup
#define __cleanup(fn)

#ifndef __always_inline
#define __always_inline	inline __attribute__((always_inline))
#endif

#ifndef __maybe_unused
#define __maybe_unused	__attribute__((unused))
#endif

#ifndef __no_context_analysis
#define __no_context_analysis
#endif

#ifndef __UNIQUE_ID
#define __bpf_cleanup_paste(a, b)		a##b
#define __bpf_cleanup_paste2(a, b)		__bpf_cleanup_paste(a, b)
#define __UNIQUE_ID(prefix)			\
	__bpf_cleanup_paste2(__bpf_cleanup_##prefix, __COUNTER__)
#endif

#define __bpf_cleanup_empty(...)
#define __bpf_cleanup_noop(...)		((void)0)
#define __bpf_cleanup_zero(...)		0
#define __bpf_cleanup_action(...)	__bpf_cleanup_noop
#define __bpf_cleanup_ptr(_scope)	((void *)(_scope))
#define __get_and_null(p, nullvalue)			\
	({						\
		typeof(p) *__ptr = &(p);		\
		typeof(p) __val = *__ptr;		\
		*__ptr = (nullvalue);			\
		__val;					\
	})
#define __bpf_cleanup_scoped_once(_var)					\
	for (void *_var __attribute__((unused)) = (void *)1; _var;	\
	     _var = (void *)0)						\
		if (0) {						\
		} else
#define __bpf_cleanup_class_zero(_type)		\
	({					\
		_type __tmp = {};		\
		__tmp;				\
	})

#define DEFINE_FREE(_name, _type, _free)				\
	static __always_inline void __maybe_unused __free_##_name(void *p) \
	{								\
		_type _T __maybe_unused = *(_type *)p;			\
	}

#define __free(_name)	__cleanup(__free_##_name)

#define no_free_ptr(p)		__get_and_null(p, (typeof(p))0)
#define return_ptr(p)		return no_free_ptr(p)
#define retain_and_null_ptr(p)	((void)__get_and_null(p, (typeof(p))0))

#define DEFINE_CLASS(_name, _type, _exit, _init, _init_args...)		\
	typedef _type class_##_name##_t;				\
	typedef _type lock_##_name##_t;					\
	static __always_inline void __maybe_unused			\
	class_##_name##_destructor(_type *p) __no_context_analysis	\
	{								\
		(void)p;						\
	}								\
	static __always_inline _type __maybe_unused			\
	class_##_name##_constructor(_init_args) __no_context_analysis	\
	{								\
		return __bpf_cleanup_class_zero(_type);			\
	}

#define EXTEND_CLASS_COND(_name, ext, _cond, _init, _init_args...)	\
	typedef lock_##_name##_t lock_##_name##ext##_t;			\
	typedef class_##_name##_t class_##_name##ext##_t;		\
	static __always_inline void __maybe_unused			\
	class_##_name##ext##_destructor(class_##_name##_t *p)		\
	{								\
		(void)p;						\
	}								\
	static __always_inline class_##_name##_t __maybe_unused		\
	class_##_name##ext##_constructor(_init_args)			\
		__no_context_analysis					\
	{								\
		return __bpf_cleanup_class_zero(class_##_name##_t);	\
	}

#define EXTEND_CLASS(_name, ext, _init, _init_args...)			\
	EXTEND_CLASS_COND(_name, ext, 0, _init, _init_args)

#define CLASS(_name, var)						\
	class_##_name##_t var __maybe_unused				\
		__cleanup(class_##_name##_destructor) =			\
		class_##_name##_constructor

#define CLASS_INIT(_name, _var, _init_expr)				\
	class_##_name##_t _var __maybe_unused				\
		__cleanup(class_##_name##_destructor) =			\
		__bpf_cleanup_class_zero(class_##_name##_t)

#define scoped_class(_name, _var, args...)	__bpf_cleanup_scoped_once(_var)

#define __DEFINE_CLASS_IS_CONDITIONAL(_name, _is_cond)			\
	static const int class_##_name##_is_conditional __maybe_unused = \
		!!(_is_cond)

#define __DEFINE_BPF_GUARD_ACCESSORS(_name, _is_cond)			\
	__DEFINE_CLASS_IS_CONDITIONAL(_name, _is_cond);		\
	static __always_inline void * __maybe_unused			\
	class_##_name##_lock_ptr(class_##_name##_t *_T)			\
	{								\
		(void)_T;						\
		return (void *)1;					\
	}								\
	static __always_inline int __maybe_unused			\
	class_##_name##_lock_err(class_##_name##_t *_T)			\
	{								\
		(void)_T;						\
		return 0;						\
	}

#define DEFINE_CLASS_IS_UNCONDITIONAL(_name)	\
	__DEFINE_BPF_GUARD_ACCESSORS(_name, 0)
#define DEFINE_CLASS_IS_GUARD(_name)		\
	__DEFINE_BPF_GUARD_ACCESSORS(_name, 0)
#define DEFINE_CLASS_IS_COND_GUARD(_name)	\
	__DEFINE_BPF_GUARD_ACCESSORS(_name, 1)
#define __guard_ptr(_name)	class_##_name##_lock_ptr
#define __guard_err(_name)	class_##_name##_lock_err
#define __is_cond_ptr(_name)	class_##_name##_is_conditional

#define DEFINE_GUARD(_name, _type, _lock, _unlock)		\
	DEFINE_CLASS(_name, _type, /* no-op */,			\
		     __bpf_cleanup_class_zero(_type), _type _T);	\
	DEFINE_CLASS_IS_GUARD(_name)

#define DEFINE_GUARD_COND_4(_name, _ext, _lock, _cond)		\
	EXTEND_CLASS_COND(_name, _ext, 0,			\
			  __bpf_cleanup_class_zero(class_##_name##_t), \
			  class_##_name##_t _T);			\
	DEFINE_CLASS_IS_COND_GUARD(_name##_ext)
#define DEFINE_GUARD_COND_3(_name, _ext, _lock)			\
	DEFINE_GUARD_COND_4(_name, _ext, _lock, _RET)
#define __bpf_cleanup_pick_cond(_1, _2, _3, _4, name, ...)	name
#define DEFINE_GUARD_COND(args...)				\
	__bpf_cleanup_pick_cond(args, DEFINE_GUARD_COND_4,	\
				DEFINE_GUARD_COND_3)(args)
#define guard				__bpf_cleanup_action

#define ACQUIRE(_name, _var)		CLASS(_name, _var)
#define ACQUIRE_ERR(_name, _var)	__guard_err(_name)(_var)

#define scoped_guard(_name, args...)	__bpf_cleanup_scoped_once(scope)
#define scoped_cond_guard(_name, _fail, args...)	\
	scoped_guard(_name, args)

#define __DEFINE_UNLOCK_GUARD(_name, _type, _unlock, ...)		\
	typedef _type lock_##_name##_t;				\
	typedef struct {						\
		_type *lock;						\
		__VA_ARGS__;						\
	} class_##_name##_t;						\
	static __always_inline void __maybe_unused			\
	class_##_name##_destructor(class_##_name##_t *_T)		\
		__no_context_analysis					\
	{								\
		(void)_T;						\
	}								\
	static __always_inline void * __maybe_unused			\
	class_##_name##_lock_ptr(class_##_name##_t *_T)			\
	{								\
		return _T && _T->lock ? (void *)_T->lock : (void *)1;	\
	}								\
	static __always_inline int __maybe_unused			\
	class_##_name##_lock_err(class_##_name##_t *_T)			\
	{								\
		(void)_T;						\
		return 0;						\
	}

#define __DEFINE_LOCK_GUARD_1(_name, _type, _lock)			\
	static __always_inline class_##_name##_t __maybe_unused		\
	class_##_name##_constructor(_type *l) __no_context_analysis	\
	{								\
		class_##_name##_t _t = { .lock = l };			\
		return _t;						\
	}

#define __DEFINE_LOCK_GUARD_0(_name, _lock)				\
	static __always_inline class_##_name##_t __maybe_unused		\
	class_##_name##_constructor(void) __no_context_analysis		\
	{								\
		class_##_name##_t _t = { .lock = (void *)1 };		\
		return _t;						\
	}

#define DEFINE_LOCK_GUARD_1(_name, _type, _lock, _unlock, ...)		\
	__DEFINE_CLASS_IS_CONDITIONAL(_name, 0);			\
	__DEFINE_UNLOCK_GUARD(_name, _type, _unlock, __VA_ARGS__)	\
	__DEFINE_LOCK_GUARD_1(_name, _type, _lock)

#define DEFINE_LOCK_GUARD_0(_name, _lock, _unlock, ...)			\
	__DEFINE_CLASS_IS_CONDITIONAL(_name, 0);			\
	__DEFINE_UNLOCK_GUARD(_name, void, _unlock, __VA_ARGS__)	\
	__DEFINE_LOCK_GUARD_0(_name, _lock)

#define DEFINE_LOCK_GUARD_1_COND_4(_name, _ext, _lock, _cond)		\
	__DEFINE_CLASS_IS_CONDITIONAL(_name##_ext, 1);			\
	typedef lock_##_name##_t lock_##_name##_ext##_t;		\
	typedef class_##_name##_t class_##_name##_ext##_t;		\
	static __always_inline void __maybe_unused			\
	class_##_name##_ext##_destructor(class_##_name##_t *_T)		\
	{								\
		(void)_T;						\
	}								\
	static __always_inline class_##_name##_t __maybe_unused		\
	class_##_name##_ext##_constructor(lock_##_name##_t *l)		\
		__no_context_analysis					\
	{								\
		class_##_name##_t _t = { .lock = l };			\
		return _t;						\
	}								\
	static __always_inline void * __maybe_unused			\
	class_##_name##_ext##_lock_ptr(class_##_name##_t *_T)		\
	{								\
		return class_##_name##_lock_ptr(_T);			\
	}								\
	static __always_inline int __maybe_unused			\
	class_##_name##_ext##_lock_err(class_##_name##_t *_T)		\
	{								\
		return class_##_name##_lock_err(_T);			\
	}

#define DEFINE_LOCK_GUARD_1_COND_3(_name, _ext, _lock)			\
	DEFINE_LOCK_GUARD_1_COND_4(_name, _ext, _lock, _RET)
#define DEFINE_LOCK_GUARD_1_COND(args...)				\
	__bpf_cleanup_pick_cond(args, DEFINE_LOCK_GUARD_1_COND_4,	\
				DEFINE_LOCK_GUARD_1_COND_3)(args)

#define DECLARE_LOCK_GUARD_1_ATTRS(_name, _lock, _unlock)		\
	static __always_inline void __maybe_unused			\
	__class_##_name##_cleanup_ctx(class_##_name##_t **_T)		\
		__no_context_analysis					\
	{								\
		(void)_T;						\
	}
#define DECLARE_LOCK_GUARD_0_ATTRS	__bpf_cleanup_empty
#define WITH_LOCK_GUARD_1_ATTRS(_name, _T)  class_##_name##_constructor(_T)

#endif /* _LINUX_CLEANUP_H */
