/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: linux/cleanup.h
 *
 * The real cleanup.h provides scope-based resource management using
 * __attribute__((__cleanup__)), DEFINE_GUARD, guard(), CLASS, etc.
 * These rely on GCC/Clang __cleanup__ attribute which is not supported
 * in BPF context (BPF verifier does not model stack-based cleanup).
 *
 * Stub out all cleanup macros so that sched.h's guard(preempt)() calls
 * and similar patterns compile without error.
 */
#ifndef _LINUX_CLEANUP_H
#define _LINUX_CLEANUP_H

/* __cleanup is used for scope-based cleanup; stub it out in BPF context. */
#define __cleanup(fn)

/* DEFINE_GUARD defines a guard type (class_<name>_t) and its constructor/destructor.
 * Stub it out so guard(preempt)() and similar calls compile as no-ops. */
#define DEFINE_GUARD(_name, _type, _lock, _unlock)
#define DEFINE_GUARD_COND_4(_name, _ext, _lock, _cond)
#define DEFINE_GUARD_COND_3(_name, _ext, _lock)
#define DEFINE_GUARD_COND(X...)

/* CLASS creates a scoped variable; stub to nothing in BPF context. */
#define CLASS(_name, var)

/* guard(name)(args) acquires a lock for the current scope.
 * In BPF context, stub it out as a no-op expression. */
#define guard(_name)    __bpf_guard_noop_##_name
#define __bpf_guard_noop_preempt        __bpf_guard_noop_fn
#define __bpf_guard_noop_fn(...)        ((void)0)

/* scoped_guard and scoped_cond_guard: stub to just execute the body. */
#define scoped_guard(_name, args...)    if (1)
#define scoped_cond_guard(_name, _fail, args...)    if (1)

/* ACQUIRE and related macros */
#define ACQUIRE(_name, _var)
#define ACQUIRE_ERR(_name, _var)        0

/* __free is used with __cleanup for auto-free; stub it out. */
#define __free(_freefn)

/* no_free_ptr: returns pointer and prevents auto-free; just return the pointer. */
#define no_free_ptr(p)  (p)

/* return_ptr: return a pointer from a scoped block. */
#define return_ptr(p)   (p)

/* DEFINE_FREE defines a type-specific cleanup function for use with __free().
 * Stub it out as a no-op in BPF context. */
#define DEFINE_FREE(_name, _type, _free)

/* DEFINE_LOCK_GUARD_1 and DEFINE_LOCK_GUARD_0 define guard types for locks.
 * Stub them out as no-ops in BPF context. */
#define DEFINE_LOCK_GUARD_1(_name, _type, _lock, _unlock, ...)
#define DEFINE_LOCK_GUARD_0(_name, _lock, _unlock, ...)
#define DEFINE_LOCK_GUARD_1_COND_4(_name, _ext, _lock, _cond)
#define DEFINE_LOCK_GUARD_1_COND_3(_name, _ext, _lock)
#define DEFINE_LOCK_GUARD_1_COND(X...)

/* DECLARE_LOCK_GUARD_1_ATTRS and WITH_LOCK_GUARD_1_ATTRS are used in mutex.h
 * and other lock headers to declare lock guard types with context analysis attrs.
 * Stub them out as no-ops in BPF context. */
#define DECLARE_LOCK_GUARD_1_ATTRS(_name, _lock, _unlock)
#define DECLARE_LOCK_GUARD_0_ATTRS(_name, _lock, _unlock)
#define WITH_LOCK_GUARD_1_ATTRS(_name, _T)  (_T)

/* NOTE: IS_ERR_OR_NULL is defined as a static inline function in linux/err.h.
 * Do NOT define it as a macro here as that would conflict with err.h's definition. */

#endif /* _LINUX_CLEANUP_H */
