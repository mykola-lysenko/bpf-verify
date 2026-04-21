/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: asm/local.h
 *
 * The real asm/local.h provides x86-specific local_t atomic operations
 * using inline assembly (GEN_BINARY_RMWcc etc.) which cannot be compiled
 * for BPF targets.
 *
 * Provide a minimal stub that defines local_t and no-op operations.
 * These are only used in performance-critical paths that are not exercised
 * by the BPF harness.
 */
#ifndef _ASM_X86_LOCAL_H
#define _ASM_X86_LOCAL_H

#include <linux/types.h>

typedef struct {
    long counter;
} local_t;

#define LOCAL_INIT(i)   { (i) }

static inline long local_read(const local_t *l)  { return l->counter; }
static inline void local_set(local_t *l, long i) { l->counter = i; }
static inline void local_inc(local_t *l)         { l->counter++; }
static inline void local_dec(local_t *l)         { l->counter--; }
static inline void local_add(long i, local_t *l) { l->counter += i; }
static inline void local_sub(long i, local_t *l) { l->counter -= i; }

static inline bool local_sub_and_test(long i, local_t *l)
{ l->counter -= i; return l->counter == 0; }

static inline bool local_dec_and_test(local_t *l)
{ return --l->counter == 0; }

static inline bool local_inc_and_test(local_t *l)
{ return ++l->counter == 0; }

static inline bool local_add_negative(long i, local_t *l)
{ l->counter += i; return l->counter < 0; }

static inline long local_add_return(long i, local_t *l)
{ l->counter += i; return l->counter; }

static inline long local_sub_return(long i, local_t *l)
{ l->counter -= i; return l->counter; }

static inline long local_cmpxchg(local_t *l, long old, long new)
{
    long val = l->counter;
    if (val == old) l->counter = new;
    return val;
}

static inline bool local_try_cmpxchg(local_t *l, long *old, long new)
{
    long val = l->counter;
    if (val == *old) { l->counter = new; return true; }
    *old = val; return false;
}

static inline long local_xchg(local_t *l, long n)
{ long old = l->counter; l->counter = n; return old; }

#endif /* _ASM_X86_LOCAL_H */
