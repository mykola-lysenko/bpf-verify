/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF shim: asm/local64.h
 *
 * asm/local64.h is a mandatory-y generated header (arch/x86/include/generated/asm/local64.h).
 * It is not present in an unbuilt kernel tree.
 *
 * On x86-64 (BITS_PER_LONG == 64), the generic asm-generic/local64.h would include
 * asm/local.h (which uses GEN_BINARY_RMWcc inline assembly, incompatible with BPF).
 * Instead, we implement local64_t directly in terms of atomic64_t, which our
 * atomic.h shim already handles safely.
 */
#ifndef _ASM_X86_LOCAL64_H
#define _ASM_X86_LOCAL64_H

#include <linux/types.h>
#include <linux/atomic.h>

typedef struct {
	atomic64_t a;
} local64_t;

#define LOCAL64_INIT(i)			{ ATOMIC64_INIT(i) }
#define local64_read(l)			atomic64_read(&(l)->a)
#define local64_set(l, i)		atomic64_set(&(l)->a, (i))
#define local64_inc(l)			atomic64_inc(&(l)->a)
#define local64_dec(l)			atomic64_dec(&(l)->a)
#define local64_add(i, l)		atomic64_add((i), &(l)->a)
#define local64_sub(i, l)		atomic64_sub((i), &(l)->a)
#define local64_sub_and_test(i, l)	atomic64_sub_and_test((i), &(l)->a)
#define local64_dec_and_test(l)		atomic64_dec_and_test(&(l)->a)
#define local64_inc_and_test(l)		atomic64_inc_and_test(&(l)->a)
#define local64_add_negative(i, l)	atomic64_add_negative((i), &(l)->a)
#define local64_add_return(i, l)	atomic64_add_return((i), &(l)->a)
#define local64_sub_return(i, l)	atomic64_sub_return((i), &(l)->a)
#define local64_inc_return(l)		atomic64_inc_return(&(l)->a)
#define local64_cmpxchg(l, o, n)	atomic64_cmpxchg(&(l)->a, (o), (n))
#define local64_try_cmpxchg(l, po, n)	atomic64_try_cmpxchg(&(l)->a, (po), (n))
#define local64_xchg(l, n)		atomic64_xchg(&(l)->a, (n))
#define local64_add_unless(l, a, u)	atomic64_add_unless(&(l)->a, (a), (u))
#define local64_inc_not_zero(l)		atomic64_inc_not_zero(&(l)->a)

#define __local64_inc(l)	local64_set((l), local64_read(l) + 1)
#define __local64_dec(l)	local64_set((l), local64_read(l) - 1)
#define __local64_add(i, l)	local64_set((l), local64_read(l) + (i))
#define __local64_sub(i, l)	local64_set((l), local64_read(l) - (i))

#endif /* _ASM_X86_LOCAL64_H */
