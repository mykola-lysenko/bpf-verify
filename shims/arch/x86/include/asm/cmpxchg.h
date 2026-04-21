/* BPF shim: asm/cmpxchg.h
 * x86 cmpxchg.h uses LOCK CMPXCHG inline asm not valid in BPF.
 * Provide BPF-safe implementations using __sync builtins.
 */
#ifndef _ASM_X86_CMPXCHG_H
#define _ASM_X86_CMPXCHG_H

/* arch_xchg: atomically exchange *ptr with val, return old value */
#define arch_xchg(ptr, val) \
__sync_lock_test_and_set(ptr, val)

/* arch_cmpxchg: compare and exchange */
#define arch_cmpxchg(ptr, old, new) \
__sync_val_compare_and_swap(ptr, old, new)

/* arch_try_cmpxchg: try compare and exchange, update *old on failure */
#define arch_try_cmpxchg(ptr, pold, new) \
({ \
typeof(*(ptr)) __old = *(pold); \
typeof(*(ptr)) __prev = __sync_val_compare_and_swap(ptr, __old, new); \
if (__prev != __old) *(pold) = __prev; \
(__prev == __old); \
})

/* arch_cmpxchg64: 64-bit compare and exchange */
#define arch_cmpxchg64(ptr, old, new) \
__sync_val_compare_and_swap(ptr, old, new)

/* arch_xchg_relaxed, arch_cmpxchg_relaxed, arch_cmpxchg_acquire, arch_cmpxchg_release */
#define arch_xchg_relaxed(ptr, val)arch_xchg(ptr, val)
#define arch_cmpxchg_relaxed(ptr, old, new)arch_cmpxchg(ptr, old, new)
#define arch_cmpxchg_acquire(ptr, old, new)arch_cmpxchg(ptr, old, new)
#define arch_cmpxchg_release(ptr, old, new)arch_cmpxchg(ptr, old, new)
#define arch_try_cmpxchg_relaxed(ptr, pold, new) arch_try_cmpxchg(ptr, pold, new)
#define arch_try_cmpxchg_acquire(ptr, pold, new) arch_try_cmpxchg(ptr, pold, new)
#define arch_try_cmpxchg_release(ptr, pold, new) arch_try_cmpxchg(ptr, pold, new)

/* cmpxchg_double stubs */
#define arch_cmpxchg_double(p1, p2, o1, o2, n1, n2) (0)
#define arch_cmpxchg_double_local(p1, p2, o1, o2, n1, n2) (0)

#endif /* _ASM_X86_CMPXCHG_H */
