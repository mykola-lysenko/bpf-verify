/* BPF shim: linux/slab.h
 *
 * The kernel's slab.h pulls in deep MM infrastructure (kmem_cache,
 * page allocator, NUMA policies) that is incompatible with BPF.
 * This shim provides stub allocator functions that the pipeline's
 * harness overrides anyway.
 */
#ifndef _LINUX_SLAB_H
#define _LINUX_SLAB_H

#include <linux/types.h>
#include <linux/gfp.h>

#define __bpf_slab_noop(...)		do { } while (0)
#define __bpf_slab_null(...)		((void *)0)

#define SLAB_HWCACHE_ALIGN	0x00002000U
#define SLAB_PANIC		0x00040000U
#define SLAB_ACCOUNT		0x04000000U

#define ZERO_SIZE_PTR		((void *)16)
#define ZERO_OR_NULL_PTR(x)	((unsigned long)(x) <= (unsigned long)ZERO_SIZE_PTR)

struct kmem_cache {
	unsigned int object_size;
	const char *name;
};
struct list_lru;

#define __BPF_SLAB_PTR_FN(name, args, used) \
	static inline void *name args { return __bpf_slab_null used; }
#define __BPF_SLAB_VOID_FN(name, args, used) \
	static inline void name args { __bpf_slab_noop used; }

__BPF_SLAB_PTR_FN(__bpf_slab_alloc, (size_t size, gfp_t flags), (size, flags))
__BPF_SLAB_PTR_FN(__bpf_slab_alloc_node, (size_t size, gfp_t flags, int node), (size, flags, node))
__BPF_SLAB_PTR_FN(__bpf_slab_alloc_array, (size_t n, size_t size, gfp_t flags), (n, size, flags))
__BPF_SLAB_PTR_FN(__bpf_slab_alloc_array_node, (size_t n, size_t size, gfp_t flags, int node), (n, size, flags, node))
__BPF_SLAB_PTR_FN(__bpf_slab_realloc, (const void *p, size_t size, gfp_t flags), (p, size, flags))
__BPF_SLAB_PTR_FN(__bpf_slab_realloc_array, (void *p, size_t n, size_t size, gfp_t flags), (p, n, size, flags))
__BPF_SLAB_PTR_FN(__bpf_slab_realloc_node, (const void *p, size_t size, gfp_t flags, int node), (p, size, flags, node))
__BPF_SLAB_PTR_FN(__bpf_kmem_cache_alloc, (struct kmem_cache *s, gfp_t flags), (s, flags))
__BPF_SLAB_PTR_FN(__bpf_kmem_cache_alloc_node, (struct kmem_cache *s, gfp_t flags, int node), (s, flags, node))
__BPF_SLAB_PTR_FN(__bpf_kmem_cache_alloc_lru, (struct kmem_cache *s, struct list_lru *lru, gfp_t flags), (s, lru, flags))
__BPF_SLAB_VOID_FN(__bpf_slab_free, (const void *p), (p))
__BPF_SLAB_VOID_FN(__bpf_slab_free_bulk, (size_t size, void **p), (size, p))
__BPF_SLAB_VOID_FN(__bpf_slab_free_sensitive, (const void *p, size_t len), (p, len))
__BPF_SLAB_VOID_FN(__bpf_kmem_cache_free, (struct kmem_cache *s, void *p), (s, p))
__BPF_SLAB_VOID_FN(__bpf_kmem_cache_free_bulk, (struct kmem_cache *s, size_t size, void **p), (s, size, p))
__BPF_SLAB_VOID_FN(__bpf_kmem_cache_destroy, (struct kmem_cache *s), (s))

#undef __BPF_SLAB_VOID_FN
#undef __BPF_SLAB_PTR_FN

static inline unsigned int __bpf_kmem_cache_size(struct kmem_cache *s) { return s ? s->object_size : 0; }
static inline size_t __bpf_ksize(const void *p) { __bpf_slab_noop(p); return 0; }
static inline size_t __bpf_kmalloc_size_roundup(size_t size) { return size; }

#ifndef kmalloc
#define kmalloc		__bpf_slab_alloc
#endif
#ifndef kzalloc
#define kzalloc		__bpf_slab_alloc
#endif
#ifndef kcalloc
#define kcalloc		__bpf_slab_alloc_array
#endif
#ifndef krealloc
#define krealloc	__bpf_slab_realloc
#endif
#ifndef kmalloc_array
#define kmalloc_array	__bpf_slab_alloc_array
#endif
#ifndef krealloc_array
#define krealloc_array	__bpf_slab_realloc_array
#endif
#ifndef kmalloc_node
#define kmalloc_node	__bpf_slab_alloc_node
#endif

#ifndef kmalloc_track_caller
#define kmalloc_track_caller(size, flags) \
	kmalloc((size), (flags))
#endif
#ifndef kmalloc_node_track_caller
#define kmalloc_node_track_caller(size, flags, node) \
	kmalloc_node((size), (flags), (node))
#endif

#ifndef kzalloc_node
#define kzalloc_node(size, flags, node)	kmalloc_node((size), (flags) | __GFP_ZERO, (node))
#endif

#ifndef kmalloc_array_node
#define kmalloc_array_node	__bpf_slab_alloc_array_node
#endif

#ifndef kcalloc_node
#define kcalloc_node(n, size, flags, node) \
	kmalloc_array_node((n), (size), (flags) | __GFP_ZERO, (node))
#endif

#ifndef kmalloc_nolock
#define kmalloc_nolock	__bpf_slab_alloc_node
#endif

#ifndef kfree
#define kfree		__bpf_slab_free
#endif
#ifndef kfree_sensitive
#define kfree_sensitive	__bpf_slab_free
#endif
#ifndef kfree_nolock
#define kfree_nolock	__bpf_slab_free
#endif
#ifndef kfree_bulk
#define kfree_bulk	__bpf_slab_free_bulk
#endif
#ifndef kvfree
#define kvfree		__bpf_slab_free
#endif
#ifndef kvfree_sensitive
#define kvfree_sensitive	__bpf_slab_free_sensitive
#endif

#ifndef kmem_cache_alloc
#define kmem_cache_alloc	__bpf_kmem_cache_alloc
#endif
#ifndef kmem_cache_alloc_node
#define kmem_cache_alloc_node	__bpf_kmem_cache_alloc_node
#endif
#ifndef kmem_cache_alloc_lru
#define kmem_cache_alloc_lru	__bpf_kmem_cache_alloc_lru
#endif

#ifndef kmem_cache_zalloc
#define kmem_cache_zalloc(s, flags)	kmem_cache_alloc((s), (flags) | __GFP_ZERO)
#endif

#ifndef kmem_cache_free
#define kmem_cache_free		__bpf_kmem_cache_free
#endif
#ifndef kmem_cache_free_bulk
#define kmem_cache_free_bulk	__bpf_kmem_cache_free_bulk
#endif

#ifndef kmem_cache_create
#define kmem_cache_create(...)		((struct kmem_cache *)0)
#endif
#ifndef kmem_cache_create_usercopy
#define kmem_cache_create_usercopy(...)	((struct kmem_cache *)0)
#endif
#ifndef kmem_cache_destroy
#define kmem_cache_destroy	__bpf_kmem_cache_destroy
#endif

#ifndef kmem_cache_size
#define kmem_cache_size		__bpf_kmem_cache_size
#endif

#ifndef ksize
#define ksize			__bpf_ksize
#endif

#ifndef kmalloc_size_roundup
#define kmalloc_size_roundup	__bpf_kmalloc_size_roundup
#endif

#ifndef kvmalloc
#define kvmalloc	__bpf_slab_alloc
#endif
#ifndef kvmalloc_node
#define kvmalloc_node	__bpf_slab_alloc_node
#endif
#ifndef kvzalloc
#define kvzalloc(size, flags)		kvmalloc((size), (flags) | __GFP_ZERO)
#endif
#ifndef kvzalloc_node
#define kvzalloc_node(size, flags, node) \
	kvmalloc_node((size), (flags) | __GFP_ZERO, (node))
#endif
#ifndef kvmalloc_array
#define kvmalloc_array		__bpf_slab_alloc_array
#endif
#ifndef kvmalloc_array_node
#define kvmalloc_array_node	__bpf_slab_alloc_array_node
#endif
#ifndef kvcalloc
#define kvcalloc	__bpf_slab_alloc_array
#endif
#ifndef kvcalloc_node
#define kvcalloc_node	__bpf_slab_alloc_array_node
#endif
#ifndef kvrealloc
#define kvrealloc	__bpf_slab_realloc
#endif
#ifndef kvrealloc_node
#define kvrealloc_node	__bpf_slab_realloc_node
#endif

#ifndef size_mul
static inline size_t __bpf_size_mul(size_t a, size_t b) { return a * b; }
#define size_mul(a, b) __bpf_size_mul((a), (b))
#endif

#define __alloc_objs(KMALLOC, GFP, TYPE, COUNT) \
	((TYPE *)KMALLOC(size_mul(sizeof(TYPE), COUNT), GFP))

#ifndef kmalloc_obj
#define kmalloc_obj(P, ...) \
	__alloc_objs(kmalloc, default_gfp(__VA_ARGS__), typeof(P), 1)
#endif
#ifndef kmalloc_objs
#define kmalloc_objs(P, COUNT, ...) \
	__alloc_objs(kmalloc, default_gfp(__VA_ARGS__), typeof(P), COUNT)
#endif
#ifndef kzalloc_obj
#define kzalloc_obj(P, ...) \
	__alloc_objs(kzalloc, default_gfp(__VA_ARGS__), typeof(P), 1)
#endif
#ifndef kzalloc_objs
#define kzalloc_objs(P, COUNT, ...) \
	__alloc_objs(kzalloc, default_gfp(__VA_ARGS__), typeof(P), COUNT)
#endif

#endif /* _LINUX_SLAB_H */
