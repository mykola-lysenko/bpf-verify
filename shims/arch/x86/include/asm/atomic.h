/* BPF shim: asm/atomic.h
 *
 * x86 atomic.h uses xadd/cmpxchg inline asm that cannot be emitted for BPF.
 * Model the primitive arch_atomic hooks with plain C operations; BPF
 * verification is single-threaded, so atomic ordering is not relevant here.
 * linux/atomic's generated fallback layer derives inc/dec/test/unless helpers
 * from these primitives.
 */
#ifndef _ASM_ATOMIC_H
#define _ASM_ATOMIC_H

#include <linux/types.h>
#include <asm/barrier.h>
#include <asm/cmpxchg.h>

static inline int arch_atomic_read(const atomic_t *v)
{
	return READ_ONCE(v->counter);
}
#define arch_atomic_read arch_atomic_read

static inline void arch_atomic_set(atomic_t *v, int i)
{
	WRITE_ONCE(v->counter, i);
}
#define arch_atomic_set arch_atomic_set

static inline int arch_atomic_read_acquire(const atomic_t *v)
{
	return smp_load_acquire(&v->counter);
}
#define arch_atomic_read_acquire arch_atomic_read_acquire

static inline void arch_atomic_set_release(atomic_t *v, int i)
{
	smp_store_release(&v->counter, i);
}
#define arch_atomic_set_release arch_atomic_set_release

#define __BPF_ATOMIC_FETCH_OP(prefix, type, value_type, op, c_op)	\
static inline value_type prefix##_fetch_##op(value_type i, type *v)	\
{									\
	value_type old = READ_ONCE(v->counter);				\
	WRITE_ONCE(v->counter, old c_op i);				\
	return old;							\
}

#define __BPF_ATOMIC_RETURN_OP(prefix, type, value_type, op, c_op)	\
static inline value_type prefix##_##op##_return(value_type i, type *v)	\
{									\
	return prefix##_fetch_##op(i, v) c_op i;			\
}

#define __BPF_ATOMIC_OP(prefix, type, value_type, op)			\
static inline void prefix##_##op(value_type i, type *v)			\
{									\
	(void)prefix##_fetch_##op(i, v);				\
}

#define __BPF_ATOMIC_OPS(prefix, type, value_type)			\
__BPF_ATOMIC_FETCH_OP(prefix, type, value_type, add, +)			\
__BPF_ATOMIC_FETCH_OP(prefix, type, value_type, sub, -)			\
__BPF_ATOMIC_FETCH_OP(prefix, type, value_type, and, &)			\
__BPF_ATOMIC_FETCH_OP(prefix, type, value_type, or, |)			\
__BPF_ATOMIC_FETCH_OP(prefix, type, value_type, xor, ^)			\
__BPF_ATOMIC_RETURN_OP(prefix, type, value_type, add, +)		\
__BPF_ATOMIC_RETURN_OP(prefix, type, value_type, sub, -)		\
__BPF_ATOMIC_OP(prefix, type, value_type, add)				\
__BPF_ATOMIC_OP(prefix, type, value_type, sub)				\
__BPF_ATOMIC_OP(prefix, type, value_type, and)				\
__BPF_ATOMIC_OP(prefix, type, value_type, or)				\
__BPF_ATOMIC_OP(prefix, type, value_type, xor)

__BPF_ATOMIC_OPS(arch_atomic, atomic_t, int)

#define arch_atomic_fetch_add arch_atomic_fetch_add
#define arch_atomic_fetch_sub arch_atomic_fetch_sub
#define arch_atomic_fetch_and arch_atomic_fetch_and
#define arch_atomic_fetch_or arch_atomic_fetch_or
#define arch_atomic_fetch_xor arch_atomic_fetch_xor
#define arch_atomic_add_return arch_atomic_add_return
#define arch_atomic_sub_return arch_atomic_sub_return
#define arch_atomic_add arch_atomic_add
#define arch_atomic_sub arch_atomic_sub
#define arch_atomic_and arch_atomic_and
#define arch_atomic_or arch_atomic_or
#define arch_atomic_xor arch_atomic_xor

static inline int arch_atomic_xchg(atomic_t *v, int new)
{
	return arch_xchg(&v->counter, new);
}
#define arch_atomic_xchg arch_atomic_xchg

static inline int arch_atomic_cmpxchg(atomic_t *v, int old, int new)
{
	return arch_cmpxchg(&v->counter, old, new);
}
#define arch_atomic_cmpxchg arch_atomic_cmpxchg

static inline bool arch_atomic_try_cmpxchg(atomic_t *v,
						    int *old,
						    int new)
{
	return arch_try_cmpxchg(&v->counter, old, new);
}
#define arch_atomic_try_cmpxchg arch_atomic_try_cmpxchg

#ifdef CONFIG_64BIT
static inline s64 arch_atomic64_read(const atomic64_t *v)
{
	return READ_ONCE(v->counter);
}
#define arch_atomic64_read arch_atomic64_read

static inline void arch_atomic64_set(atomic64_t *v, s64 i)
{
	WRITE_ONCE(v->counter, i);
}
#define arch_atomic64_set arch_atomic64_set

static inline s64 arch_atomic64_read_acquire(const atomic64_t *v)
{
	return smp_load_acquire(&v->counter);
}
#define arch_atomic64_read_acquire arch_atomic64_read_acquire

static inline void arch_atomic64_set_release(atomic64_t *v, s64 i)
{
	smp_store_release(&v->counter, i);
}
#define arch_atomic64_set_release arch_atomic64_set_release

__BPF_ATOMIC_OPS(arch_atomic64, atomic64_t, s64)

#define arch_atomic64_fetch_add arch_atomic64_fetch_add
#define arch_atomic64_fetch_sub arch_atomic64_fetch_sub
#define arch_atomic64_fetch_and arch_atomic64_fetch_and
#define arch_atomic64_fetch_or arch_atomic64_fetch_or
#define arch_atomic64_fetch_xor arch_atomic64_fetch_xor
#define arch_atomic64_add_return arch_atomic64_add_return
#define arch_atomic64_sub_return arch_atomic64_sub_return
#define arch_atomic64_add arch_atomic64_add
#define arch_atomic64_sub arch_atomic64_sub
#define arch_atomic64_and arch_atomic64_and
#define arch_atomic64_or arch_atomic64_or
#define arch_atomic64_xor arch_atomic64_xor

static inline s64 arch_atomic64_xchg(atomic64_t *v, s64 new)
{
	return arch_xchg(&v->counter, new);
}
#define arch_atomic64_xchg arch_atomic64_xchg

static inline s64 arch_atomic64_cmpxchg(atomic64_t *v,
						 s64 old,
						 s64 new)
{
	return arch_cmpxchg64(&v->counter, old, new);
}
#define arch_atomic64_cmpxchg arch_atomic64_cmpxchg

static inline bool arch_atomic64_try_cmpxchg(atomic64_t *v,
						      s64 *old,
						      s64 new)
{
	return arch_try_cmpxchg(&v->counter, old, new);
}
#define arch_atomic64_try_cmpxchg arch_atomic64_try_cmpxchg
#endif /* CONFIG_64BIT */

#undef __BPF_ATOMIC_OPS
#undef __BPF_ATOMIC_OP
#undef __BPF_ATOMIC_RETURN_OP
#undef __BPF_ATOMIC_FETCH_OP

#endif /* _ASM_ATOMIC_H */
