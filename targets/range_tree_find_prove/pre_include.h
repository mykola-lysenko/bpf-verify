#pragma clang attribute push(__attribute__((internal_linkage)), apply_to=function)
#include "{ksrc}/lib/rbtree.c"
#pragma clang attribute pop
#include <linux/errno.h>
#define _LINUX_BPF_H 1
#define NUMA_NO_NODE (-1)
static void *__bpf_range_tree_alloc(size_t size, unsigned int flags, int node);
static void __bpf_range_tree_free(const void *ptr);
#define kmalloc_nolock(size, flags, node) __bpf_range_tree_alloc((size), (flags), (node))
#define kfree_nolock(ptr) __bpf_range_tree_free((ptr))
