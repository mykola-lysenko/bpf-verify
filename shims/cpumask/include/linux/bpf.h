/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local BPF surface for kernel/bpf/cpumask.c. */
#ifndef _LINUX_BPF_H
#define _LINUX_BPF_H

#include <linux/types.h>
#include <linux/errno.h>

#ifndef NULL
#define NULL ((void *)0)
#endif
#ifndef offsetof
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#define __init
#define __bpf_kfunc
#define __bpf_kfunc_start_defs()
#define __bpf_kfunc_end_defs()
#define CFI_NOSEAL(fn)
#define THIS_MODULE ((void *)0)
#define BUILD_BUG_ON(cond) ((void)sizeof(char[1 - 2 * !!(cond)]))
#define late_initcall(fn)

#define BPF_PROG_TYPE_TRACING 1
#define BPF_PROG_TYPE_STRUCT_OPS 2
#define BPF_PROG_TYPE_SYSCALL 3

#define KF_ACQUIRE (1U << 0)
#define KF_RET_NULL (1U << 1)
#define KF_RELEASE (1U << 2)
#define KF_RCU (1U << 3)

typedef struct {
	int refs;
} refcount_t;

static inline void refcount_set(refcount_t *ref, int value)
{
	ref->refs = value;
}

static inline void refcount_inc(refcount_t *ref)
{
	ref->refs++;
}

static inline bool refcount_dec_and_test(refcount_t *ref)
{
	ref->refs--;
	return ref->refs == 0;
}

static inline int refcount_read(const refcount_t *ref)
{
	return ref->refs;
}

static inline void *__bpf_cpumask_memset(void *dst, int c, size_t len)
{
	unsigned char *p = dst;
	size_t i;

	for (i = 0; i < len && i < 64; i++)
		p[i] = (unsigned char)c;
	return dst;
}

#define memset(dst, c, len) __bpf_cpumask_memset((dst), (c), (len))

#endif /* _LINUX_BPF_H */
