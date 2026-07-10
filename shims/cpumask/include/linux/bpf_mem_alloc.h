/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local BPF memory allocator surface for kernel/bpf/cpumask.c. */
#ifndef _LINUX_BPF_MEM_ALLOC_H
#define _LINUX_BPF_MEM_ALLOC_H

#include <linux/types.h>

struct bpf_mem_alloc {
	u32 elem_size;
};

static unsigned char __bpf_cpumask_pool[64] __attribute__((aligned(8)));
static u32 __bpf_cpumask_allocs;
static u32 __bpf_cpumask_frees;

static inline int bpf_mem_alloc_init(struct bpf_mem_alloc *ma,
				     size_t elem_size, bool percpu)
{
	(void)percpu;
	ma->elem_size = elem_size;
	__bpf_cpumask_allocs = 0;
	__bpf_cpumask_frees = 0;
	return elem_size <= sizeof(__bpf_cpumask_pool) ? 0 : -ENOMEM;
}

static inline void *bpf_mem_cache_alloc(struct bpf_mem_alloc *ma)
{
	(void)ma;
	__bpf_cpumask_allocs++;
	return __bpf_cpumask_pool;
}

static inline void bpf_mem_cache_free_rcu(struct bpf_mem_alloc *ma, void *ptr)
{
	(void)ma;
	(void)ptr;
	__bpf_cpumask_frees++;
}

#endif /* _LINUX_BPF_MEM_ALLOC_H */
