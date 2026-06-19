/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local allocator surface for kernel/bpf/crypto.c. */
#ifndef _LINUX_BPF_MEM_ALLOC_H
#define _LINUX_BPF_MEM_ALLOC_H

#include <linux/bpf.h>

struct bpf_crypto_ctx;
struct bpf_crypto_type_list;

extern struct bpf_crypto_ctx __bpf_crypto_ctx_obj;
extern struct bpf_crypto_type_list __bpf_crypto_type_node;

static u32 __bpf_crypto_allocs;
static u32 __bpf_crypto_frees;
static u32 __bpf_crypto_list_adds;
static u32 __bpf_crypto_list_dels;

static inline void *__bpf_crypto_memset(void *dst, int c, size_t len)
{
	unsigned char *d = dst;
	size_t i;

	for (i = 0; i < len && i < 512; i++)
		d[i] = (unsigned char)c;
	return dst;
}

static inline void *__bpf_crypto_alloc(size_t size, bool zero)
{
	void *ptr;

	if (size <= 64)
		ptr = &__bpf_crypto_type_node;
	else
		ptr = &__bpf_crypto_ctx_obj;
	if (zero)
		__bpf_crypto_memset(ptr, 0, size);
	__bpf_crypto_allocs++;
	return ptr;
}

#define kmalloc_obj(obj, ...) ((typeof(&(obj)))__bpf_crypto_alloc(sizeof(obj), false))
#define kzalloc_obj(obj, ...) ((typeof(&(obj)))__bpf_crypto_alloc(sizeof(obj), true))

static inline void kfree(const void *ptr)
{
	(void)ptr;
	__bpf_crypto_frees++;
}

#define memset(dst, c, len) __bpf_crypto_memset((dst), (c), (len))

#endif /* _LINUX_BPF_MEM_ALLOC_H */
