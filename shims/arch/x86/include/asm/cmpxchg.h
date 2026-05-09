/* BPF shim: asm/cmpxchg.h
 * x86 cmpxchg.h uses LOCK CMPXCHG inline asm not valid in BPF.
 * Model exchange operations as plain load/compare/store sequences. BPF
 * verification is single-threaded, so atomic ordering is not relevant here.
 */
#ifndef _ASM_X86_CMPXCHG_H
#define _ASM_X86_CMPXCHG_H

#define arch_xchg(ptr, val)					\
({								\
	typeof(*(ptr)) *__ptr = (ptr);				\
	typeof(*__ptr) __old = *__ptr;				\
	*__ptr = (typeof(*__ptr))(val);				\
	__old;							\
})

#define arch_cmpxchg(ptr, old, new)				\
({								\
	typeof(*(ptr)) *__ptr = (ptr);				\
	typeof(*__ptr) __old = (old);				\
	typeof(*__ptr) __prev = *__ptr;				\
	if (__prev == __old)					\
		*__ptr = (typeof(*__ptr))(new);			\
	__prev;							\
})

#define arch_try_cmpxchg(ptr, pold, new)			\
({								\
	typeof(*(ptr)) *__ptr = (ptr);				\
	typeof(*__ptr) *__oldp = (pold);			\
	typeof(*__ptr) __old = *__oldp;				\
	typeof(*__ptr) __prev = *__ptr;				\
	if (__prev == __old)					\
		*__ptr = (typeof(*__ptr))(new);			\
	else							\
		*__oldp = __prev;				\
	__prev == __old;					\
})

#define arch_cmpxchg64(ptr, old, new)	arch_cmpxchg(ptr, old, new)

#define arch_xchg_relaxed(ptr, val)		arch_xchg(ptr, val)
#define arch_cmpxchg_relaxed(ptr, old, new)	arch_cmpxchg(ptr, old, new)
#define arch_cmpxchg_acquire(ptr, old, new)	arch_cmpxchg(ptr, old, new)
#define arch_cmpxchg_release(ptr, old, new)	arch_cmpxchg(ptr, old, new)
#define arch_try_cmpxchg_relaxed(ptr, pold, new) \
	arch_try_cmpxchg(ptr, pold, new)
#define arch_try_cmpxchg_acquire(ptr, pold, new) \
	arch_try_cmpxchg(ptr, pold, new)
#define arch_try_cmpxchg_release(ptr, pold, new) \
	arch_try_cmpxchg(ptr, pold, new)

/* cmpxchg_double stubs */
#define arch_cmpxchg_double(p1, p2, o1, o2, n1, n2) (0)
#define arch_cmpxchg_double_local(p1, p2, o1, o2, n1, n2) (0)

#endif /* _ASM_X86_CMPXCHG_H */
