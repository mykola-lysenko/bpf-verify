/* BPF shim: asm/atomic.h
 * x86 atomic.h uses xadd/cmpxchg inline asm not valid in BPF.
 * We define only arch_atomic_* functions here; linux/atomic/atomic-instrumented.h
 * will wrap them into the public atomic_* API.
 */
#ifndef _ASM_ATOMIC_H
#define _ASM_ATOMIC_H

#include <linux/types.h>
/* Include barrier.h for smp_load_acquire / smp_store_release */
#include <asm/barrier.h>

/* atomic_t is defined in linux/types.h via asm-generic/atomic-types.h */

static __always_inline int arch_atomic_read(const atomic_t *v)
{
	return READ_ONCE(v->counter);
}
#define arch_atomic_read arch_atomic_read

static __always_inline void arch_atomic_set(atomic_t *v, int i)
{
	WRITE_ONCE(v->counter, i);
}
#define arch_atomic_set arch_atomic_set

static __always_inline int arch_atomic_read_acquire(const atomic_t *v)
{
	return smp_load_acquire(&v->counter);
}
#define arch_atomic_read_acquire arch_atomic_read_acquire

static __always_inline void arch_atomic_set_release(atomic_t *v, int i)
{
	smp_store_release(&v->counter, i);
}
#define arch_atomic_set_release arch_atomic_set_release

static __always_inline int arch_atomic_add_return(int i, atomic_t *v)
{
	return i + __sync_fetch_and_add(&v->counter, i);
}
#define arch_atomic_add_return arch_atomic_add_return

static __always_inline int arch_atomic_sub_return(int i, atomic_t *v)
{
	return __sync_sub_and_fetch(&v->counter, i);
}
#define arch_atomic_sub_return arch_atomic_sub_return

static __always_inline int arch_atomic_fetch_add(int i, atomic_t *v)
{
	return __sync_fetch_and_add(&v->counter, i);
}
#define arch_atomic_fetch_add arch_atomic_fetch_add

static __always_inline int arch_atomic_fetch_sub(int i, atomic_t *v)
{
	return __sync_fetch_and_sub(&v->counter, i);
}
#define arch_atomic_fetch_sub arch_atomic_fetch_sub

static __always_inline int arch_atomic_fetch_and(int i, atomic_t *v)
{
	return __sync_fetch_and_and(&v->counter, i);
}
#define arch_atomic_fetch_and arch_atomic_fetch_and

static __always_inline int arch_atomic_fetch_or(int i, atomic_t *v)
{
	return __sync_fetch_and_or(&v->counter, i);
}
#define arch_atomic_fetch_or arch_atomic_fetch_or

static __always_inline int arch_atomic_fetch_xor(int i, atomic_t *v)
{
	return __sync_fetch_and_xor(&v->counter, i);
}
#define arch_atomic_fetch_xor arch_atomic_fetch_xor

static __always_inline int arch_atomic_xchg(atomic_t *v, int new)
{
	return __sync_lock_test_and_set(&v->counter, new);
}
#define arch_atomic_xchg arch_atomic_xchg

static __always_inline int arch_atomic_cmpxchg(atomic_t *v, int old, int new)
{
	return __sync_val_compare_and_swap(&v->counter, old, new);
}
#define arch_atomic_cmpxchg arch_atomic_cmpxchg

static __always_inline bool arch_atomic_try_cmpxchg(atomic_t *v, int *old, int new)
{
	int prev = __sync_val_compare_and_swap(&v->counter, *old, new);
	if (prev == *old)
		return true;
	*old = prev;
	return false;
}
#define arch_atomic_try_cmpxchg arch_atomic_try_cmpxchg

static __always_inline void arch_atomic_and(int i, atomic_t *v)
{
	__sync_fetch_and_and(&v->counter, i);
}
#define arch_atomic_and arch_atomic_and

static __always_inline void arch_atomic_or(int i, atomic_t *v)
{
	__sync_fetch_and_or(&v->counter, i);
}
#define arch_atomic_or arch_atomic_or

static __always_inline void arch_atomic_xor(int i, atomic_t *v)
{
	__sync_fetch_and_xor(&v->counter, i);
}
#define arch_atomic_xor arch_atomic_xor

static __always_inline void arch_atomic_add(int i, atomic_t *v)
{
	__sync_fetch_and_add(&v->counter, i);
}
#define arch_atomic_add arch_atomic_add

static __always_inline void arch_atomic_sub(int i, atomic_t *v)
{
	__sync_fetch_and_sub(&v->counter, i);
}
#define arch_atomic_sub arch_atomic_sub

static __always_inline bool arch_atomic_sub_and_test(int i, atomic_t *v)
{
	return arch_atomic_sub_return(i, v) == 0;
}
#define arch_atomic_sub_and_test arch_atomic_sub_and_test

static __always_inline bool arch_atomic_dec_and_test(atomic_t *v)
{
	return arch_atomic_sub_return(1, v) == 0;
}
#define arch_atomic_dec_and_test arch_atomic_dec_and_test

static __always_inline bool arch_atomic_inc_and_test(atomic_t *v)
{
	return arch_atomic_add_return(1, v) == 0;
}
#define arch_atomic_inc_and_test arch_atomic_inc_and_test

static __always_inline bool arch_atomic_add_negative(int i, atomic_t *v)
{
	return arch_atomic_add_return(i, v) < 0;
}
#define arch_atomic_add_negative arch_atomic_add_negative

static __always_inline void arch_atomic_inc(atomic_t *v)
{
	arch_atomic_add(1, v);
}
#define arch_atomic_inc arch_atomic_inc

static __always_inline void arch_atomic_dec(atomic_t *v)
{
	arch_atomic_sub(1, v);
}
#define arch_atomic_dec arch_atomic_dec

static __always_inline int arch_atomic_inc_return(atomic_t *v)
{
	return arch_atomic_add_return(1, v);
}
#define arch_atomic_inc_return arch_atomic_inc_return

static __always_inline int arch_atomic_dec_return(atomic_t *v)
{
	return arch_atomic_sub_return(1, v);
}
#define arch_atomic_dec_return arch_atomic_dec_return

static __always_inline int arch_atomic_fetch_add_unless(atomic_t *v, int a, int u)
{
	int c = arch_atomic_read(v);
	while (c != u) {
		int old = arch_atomic_cmpxchg(v, c, c + a);
		if (old == c)
			break;
		c = old;
	}
	return c;
}
#define arch_atomic_fetch_add_unless arch_atomic_fetch_add_unless

static __always_inline bool arch_atomic_add_unless(atomic_t *v, int a, int u)
{
	return arch_atomic_fetch_add_unless(v, a, u) != u;
}
#define arch_atomic_add_unless arch_atomic_add_unless

static __always_inline bool arch_atomic_inc_not_zero(atomic_t *v)
{
	return arch_atomic_add_unless(v, 1, 0);
}
#define arch_atomic_inc_not_zero arch_atomic_inc_not_zero

static __always_inline bool arch_atomic_inc_unless_negative(atomic_t *v)
{
	int c = arch_atomic_read(v);
	while (c >= 0) {
		int old = arch_atomic_cmpxchg(v, c, c + 1);
		if (old == c)
			return true;
		c = old;
	}
	return false;
}
#define arch_atomic_inc_unless_negative arch_atomic_inc_unless_negative

static __always_inline bool arch_atomic_dec_unless_positive(atomic_t *v)
{
	int c = arch_atomic_read(v);
	while (c <= 0) {
		int old = arch_atomic_cmpxchg(v, c, c - 1);
		if (old == c)
			return true;
		c = old;
	}
	return false;
}
#define arch_atomic_dec_unless_positive arch_atomic_dec_unless_positive

static __always_inline int arch_atomic_dec_if_positive(atomic_t *v)
{
	int c = arch_atomic_read(v);
	while (c > 0) {
		int old = arch_atomic_cmpxchg(v, c, c - 1);
		if (old == c)
			return c - 1;
		c = old;
	}
	return c;
}
#define arch_atomic_dec_if_positive arch_atomic_dec_if_positive

/* atomic64 variants - atomic64_t is defined in linux/types.h */

#ifdef CONFIG_64BIT
static __always_inline s64 arch_atomic64_read(const atomic64_t *v)
{
	return READ_ONCE(v->counter);
}
#define arch_atomic64_read arch_atomic64_read

static __always_inline void arch_atomic64_set(atomic64_t *v, s64 i)
{
	WRITE_ONCE(v->counter, i);
}
#define arch_atomic64_set arch_atomic64_set

static __always_inline s64 arch_atomic64_read_acquire(const atomic64_t *v)
{
	return smp_load_acquire(&v->counter);
}
#define arch_atomic64_read_acquire arch_atomic64_read_acquire

static __always_inline void arch_atomic64_set_release(atomic64_t *v, s64 i)
{
	smp_store_release(&v->counter, i);
}
#define arch_atomic64_set_release arch_atomic64_set_release

static __always_inline s64 arch_atomic64_add_return(s64 i, atomic64_t *v)
{
	return i + __sync_fetch_and_add(&v->counter, i);
}
#define arch_atomic64_add_return arch_atomic64_add_return

static __always_inline s64 arch_atomic64_sub_return(s64 i, atomic64_t *v)
{
	return __sync_sub_and_fetch(&v->counter, i);
}
#define arch_atomic64_sub_return arch_atomic64_sub_return

static __always_inline s64 arch_atomic64_fetch_add(s64 i, atomic64_t *v)
{
	return __sync_fetch_and_add(&v->counter, i);
}
#define arch_atomic64_fetch_add arch_atomic64_fetch_add

static __always_inline s64 arch_atomic64_fetch_sub(s64 i, atomic64_t *v)
{
	return __sync_fetch_and_sub(&v->counter, i);
}
#define arch_atomic64_fetch_sub arch_atomic64_fetch_sub

static __always_inline s64 arch_atomic64_fetch_and(s64 i, atomic64_t *v)
{
	return __sync_fetch_and_and(&v->counter, i);
}
#define arch_atomic64_fetch_and arch_atomic64_fetch_and

static __always_inline s64 arch_atomic64_fetch_or(s64 i, atomic64_t *v)
{
	return __sync_fetch_and_or(&v->counter, i);
}
#define arch_atomic64_fetch_or arch_atomic64_fetch_or

static __always_inline s64 arch_atomic64_fetch_xor(s64 i, atomic64_t *v)
{
	return __sync_fetch_and_xor(&v->counter, i);
}
#define arch_atomic64_fetch_xor arch_atomic64_fetch_xor

static __always_inline s64 arch_atomic64_xchg(atomic64_t *v, s64 new)
{
	return __sync_lock_test_and_set(&v->counter, new);
}
#define arch_atomic64_xchg arch_atomic64_xchg

static __always_inline s64 arch_atomic64_cmpxchg(atomic64_t *v, s64 old, s64 new)
{
	return __sync_val_compare_and_swap(&v->counter, old, new);
}
#define arch_atomic64_cmpxchg arch_atomic64_cmpxchg

static __always_inline bool arch_atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
{
	s64 prev = __sync_val_compare_and_swap(&v->counter, *old, new);
	if (prev == *old)
		return true;
	*old = prev;
	return false;
}
#define arch_atomic64_try_cmpxchg arch_atomic64_try_cmpxchg

static __always_inline void arch_atomic64_and(s64 i, atomic64_t *v)
{
	__sync_fetch_and_and(&v->counter, i);
}
#define arch_atomic64_and arch_atomic64_and

static __always_inline void arch_atomic64_or(s64 i, atomic64_t *v)
{
	__sync_fetch_and_or(&v->counter, i);
}
#define arch_atomic64_or arch_atomic64_or

static __always_inline void arch_atomic64_xor(s64 i, atomic64_t *v)
{
	__sync_fetch_and_xor(&v->counter, i);
}
#define arch_atomic64_xor arch_atomic64_xor

static __always_inline void arch_atomic64_add(s64 i, atomic64_t *v)
{
	__sync_fetch_and_add(&v->counter, i);
}
#define arch_atomic64_add arch_atomic64_add

static __always_inline void arch_atomic64_sub(s64 i, atomic64_t *v)
{
	__sync_fetch_and_sub(&v->counter, i);
}
#define arch_atomic64_sub arch_atomic64_sub

static __always_inline bool arch_atomic64_sub_and_test(s64 i, atomic64_t *v)
{
	return arch_atomic64_sub_return(i, v) == 0;
}
#define arch_atomic64_sub_and_test arch_atomic64_sub_and_test

static __always_inline bool arch_atomic64_dec_and_test(atomic64_t *v)
{
	return arch_atomic64_sub_return(1, v) == 0;
}
#define arch_atomic64_dec_and_test arch_atomic64_dec_and_test

static __always_inline bool arch_atomic64_inc_and_test(atomic64_t *v)
{
	return arch_atomic64_add_return(1, v) == 0;
}
#define arch_atomic64_inc_and_test arch_atomic64_inc_and_test

static __always_inline bool arch_atomic64_add_negative(s64 i, atomic64_t *v)
{
	return arch_atomic64_add_return(i, v) < 0;
}
#define arch_atomic64_add_negative arch_atomic64_add_negative

static __always_inline void arch_atomic64_inc(atomic64_t *v)
{
	arch_atomic64_add(1, v);
}
#define arch_atomic64_inc arch_atomic64_inc

static __always_inline void arch_atomic64_dec(atomic64_t *v)
{
	arch_atomic64_sub(1, v);
}
#define arch_atomic64_dec arch_atomic64_dec

static __always_inline s64 arch_atomic64_inc_return(atomic64_t *v)
{
	return arch_atomic64_add_return(1, v);
}
#define arch_atomic64_inc_return arch_atomic64_inc_return

static __always_inline s64 arch_atomic64_dec_return(atomic64_t *v)
{
	return arch_atomic64_sub_return(1, v);
}
#define arch_atomic64_dec_return arch_atomic64_dec_return

static __always_inline bool arch_atomic64_inc_not_zero(atomic64_t *v)
{
	s64 c = arch_atomic64_read(v);
	while (c) {
		s64 old = arch_atomic64_cmpxchg(v, c, c + 1);
		if (old == c)
			return true;
		c = old;
	}
	return false;
}
#define arch_atomic64_inc_not_zero arch_atomic64_inc_not_zero
#endif /* CONFIG_64BIT */

#endif /* _ASM_ATOMIC_H */
