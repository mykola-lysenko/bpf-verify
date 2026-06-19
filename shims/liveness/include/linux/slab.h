/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SLAB_H
#define _LINUX_SLAB_H

#include <linux/bpf.h>

#define GFP_KERNEL_ACCOUNT 0

struct __bpf_liveness_alloc_slot {
	unsigned char data[8192];
};

static struct __bpf_liveness_alloc_slot __bpf_liveness_allocs[16];

static inline void *__bpf_liveness_zalloc_slot(int slot, __kernel_size_t size)
{
	unsigned char *p;
	__kernel_size_t i;

	if (slot < 0 || slot >= ARRAY_SIZE(__bpf_liveness_allocs))
		return NULL;
	if (size > sizeof(__bpf_liveness_allocs[slot].data))
		return NULL;
	p = __bpf_liveness_allocs[slot].data;
	for (i = 0; i < size && i < sizeof(__bpf_liveness_allocs[slot].data); i++)
		p[i] = 0;
	return p;
}

#define kvzalloc(size, flags) \
	__bpf_liveness_zalloc_slot(__COUNTER__, (size))
#define kvzalloc_obj(obj, flags) \
	((typeof(obj) *)__bpf_liveness_zalloc_slot(__COUNTER__, sizeof(obj)))
#define kvzalloc_objs(obj, count, flags) \
	((typeof(obj) *)__bpf_liveness_zalloc_slot(__COUNTER__, sizeof(obj) * (count)))
#define kvmalloc_objs(obj, count, flags) \
	((typeof(obj) *)__bpf_liveness_zalloc_slot(__COUNTER__, sizeof(obj) * (count)))
#define kvfree(ptr) do { (void)(ptr); } while (0)

#endif /* _LINUX_SLAB_H */
