/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local BPF allocator surface for kernel/bpf/stream.c. */
#ifndef _LINUX_BPF_MEM_ALLOC_H
#define _LINUX_BPF_MEM_ALLOC_H

#include <linux/bpf.h>

#ifndef __GFP_ZERO
#define __GFP_ZERO 0x8000U
#endif

static struct bpf_stream_elem __bpf_stream_elem_pool;
static u32 __bpf_stream_allocs;
static u32 __bpf_stream_frees;

static inline void *__bpf_stream_memset(void *dst, int c, size_t len)
{
	unsigned char *d = dst;
	size_t i;

	for (i = 0; i < len && i < sizeof(__bpf_stream_elem_pool); i++)
		d[i] = (unsigned char)c;
	return dst;
}

static inline void *kmalloc_nolock(size_t size, unsigned int flags, int node)
{
	(void)node;
	if (size > sizeof(__bpf_stream_elem_pool))
		return NULL;
	if (flags & __GFP_ZERO)
		__bpf_stream_memset(&__bpf_stream_elem_pool, 0,
				    sizeof(__bpf_stream_elem_pool));
	__bpf_stream_allocs++;
	return &__bpf_stream_elem_pool;
}

static inline void kfree_nolock(void *ptr)
{
	(void)ptr;
	__bpf_stream_frees++;
}

#define memset(dst, c, len) __bpf_stream_memset((dst), (c), (len))

#endif /* _LINUX_BPF_MEM_ALLOC_H */
