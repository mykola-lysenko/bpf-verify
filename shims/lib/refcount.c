// SPDX-License-Identifier: GPL-2.0
/* BPF shim: lib/refcount.c
 * All refcount operations use plain (non-atomic) reads/writes.
 * The inline functions from <linux/refcount.h> use cmpxchg which
 * the BPF verifier rejects on stack memory, so we redefine everything. */

#include <linux/types.h>

typedef struct refcount_struct {
	int refs;
} refcount_t;

static __always_inline void refcount_set(refcount_t *r, int n)
{
	r->refs = n;
}

static __always_inline unsigned int refcount_read(const refcount_t *r)
{
	return r->refs;
}

static __always_inline bool refcount_inc_not_zero(refcount_t *r)
{
	int val = r->refs;
	if (val == 0)
		return false;
	r->refs = val + 1;
	return true;
}

static __always_inline bool refcount_dec_and_test(refcount_t *r)
{
	int val = r->refs - 1;
	r->refs = val;
	return val == 0;
}
