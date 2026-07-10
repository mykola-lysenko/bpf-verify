/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: asm/local.h */
#ifndef _ASM_X86_LOCAL_H
#define _ASM_X86_LOCAL_H

#include <linux/atomic.h>

typedef struct {
	atomic_long_t a;
} local_t;

#define LOCAL_INIT(i)	{ ATOMIC_LONG_INIT(i) }

#define local_read(l)		atomic_long_read(&(l)->a)
#define local_set(l, i)		atomic_long_set(&(l)->a, (i))
#define local_inc(l)		atomic_long_inc(&(l)->a)
#define local_dec(l)		atomic_long_dec(&(l)->a)
#define local_add(i, l)		atomic_long_add((i), &(l)->a)
#define local_sub(i, l)		atomic_long_sub((i), &(l)->a)
#define local_add_return(i, l)	atomic_long_add_return((i), &(l)->a)
#define local_sub_return(i, l)	atomic_long_sub_return((i), &(l)->a)
#define local_inc_return(l)	local_add_return(1, (l))
#define local_dec_return(l)	local_sub_return(1, (l))

static inline bool local_sub_and_test(long i, local_t *l)
{
	return local_sub_return(i, l) == 0;
}

static inline bool local_dec_and_test(local_t *l)
{
	return local_sub_and_test(1, l);
}

static inline bool local_inc_and_test(local_t *l)
{
	return local_add_return(1, l) == 0;
}

static inline bool local_add_negative(long i, local_t *l)
{
	return local_add_return(i, l) < 0;
}

static inline long local_cmpxchg(local_t *l, long old, long new)
{
	return atomic_long_cmpxchg(&(l)->a, old, new);
}

static inline long local_xchg(local_t *l, long n)
{
	return atomic_long_xchg(&(l)->a, n);
}

static inline bool local_add_unless(local_t *l, long a, long u)
{
	return atomic_long_add_unless(&(l)->a, a, u);
}

#define local_inc_not_zero(l)	local_add_unless((l), 1, 0)

#define __local_inc(l)		local_inc(l)
#define __local_dec(l)		local_dec(l)
#define __local_add(i, l)	local_add((i), (l))
#define __local_sub(i, l)	local_sub((i), (l))

#endif /* _ASM_X86_LOCAL_H */
