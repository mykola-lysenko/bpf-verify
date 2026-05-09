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

#ifndef kmalloc
static inline void *kmalloc(size_t size, gfp_t flags)
{
	return __bpf_slab_null(size, flags);
}
#endif

#ifndef kzalloc
static inline void *kzalloc(size_t size, gfp_t flags)
{
	return __bpf_slab_null(size, flags);
}
#endif

#ifndef kcalloc
static inline void *kcalloc(size_t n, size_t size, gfp_t flags)
{
	return __bpf_slab_null(n, size, flags);
}
#endif

#ifndef krealloc
static inline void *krealloc(const void *p, size_t new_size, gfp_t flags)
{
	return __bpf_slab_null(p, new_size, flags);
}
#endif

#ifndef kmalloc_array
static inline void *kmalloc_array(size_t n, size_t size, gfp_t flags)
{
	return __bpf_slab_null(n, size, flags);
}
#endif

#ifndef krealloc_array
static inline void *krealloc_array(void *p, size_t new_n, size_t new_size, gfp_t flags)
{
	return __bpf_slab_null(p, new_n, new_size, flags);
}
#endif

#ifndef kmalloc_node
static inline void *kmalloc_node(size_t size, gfp_t flags, int node)
{
	return __bpf_slab_null(size, flags, node);
}
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
static inline void *kmalloc_array_node(size_t n, size_t size, gfp_t flags,
				       int node)
{
	return __bpf_slab_null(n, size, flags, node);
}
#endif

#ifndef kcalloc_node
#define kcalloc_node(n, size, flags, node) \
	kmalloc_array_node((n), (size), (flags) | __GFP_ZERO, (node))
#endif

#ifndef kmalloc_nolock
static inline void *kmalloc_nolock(size_t size, gfp_t flags, int node)
{
	return __bpf_slab_null(size, flags, node);
}
#endif

#ifndef kfree
static inline void kfree(const void *p) { __bpf_slab_noop(p); }
#endif
#ifndef kfree_sensitive
static inline void kfree_sensitive(const void *p) { __bpf_slab_noop(p); }
#endif
#ifndef kfree_nolock
static inline void kfree_nolock(const void *p) { __bpf_slab_noop(p); }
#endif
#ifndef kfree_bulk
static inline void kfree_bulk(size_t size, void **p)
{
	__bpf_slab_noop(size, p);
}
#endif
#ifndef kvfree
static inline void kvfree(const void *p) { __bpf_slab_noop(p); }
#endif
#ifndef kvfree_sensitive
static inline void kvfree_sensitive(const void *p, size_t len)
{
	__bpf_slab_noop(p, len);
}
#endif

#ifndef kmem_cache_alloc
static inline void *kmem_cache_alloc(struct kmem_cache *s, gfp_t flags)
{
	return __bpf_slab_null(s, flags);
}
#endif

#ifndef kmem_cache_alloc_node
static inline void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t flags,
					  int node)
{
	return __bpf_slab_null(s, flags, node);
}
#endif

#ifndef kmem_cache_alloc_lru
static inline void *kmem_cache_alloc_lru(struct kmem_cache *s,
					 struct list_lru *lru, gfp_t flags)
{
	return __bpf_slab_null(s, lru, flags);
}
#endif

#ifndef kmem_cache_zalloc
#define kmem_cache_zalloc(s, flags)	kmem_cache_alloc((s), (flags) | __GFP_ZERO)
#endif

#ifndef kmem_cache_free
static inline void kmem_cache_free(struct kmem_cache *s, void *p)
{
	__bpf_slab_noop(s, p);
}
#endif
#ifndef kmem_cache_free_bulk
static inline void kmem_cache_free_bulk(struct kmem_cache *s, size_t size,
					void **p)
{
	__bpf_slab_noop(s, size, p);
}
#endif

#ifndef kmem_cache_create
#define kmem_cache_create(...)		((struct kmem_cache *)0)
#endif
#ifndef kmem_cache_create_usercopy
#define kmem_cache_create_usercopy(...)	((struct kmem_cache *)0)
#endif
#ifndef kmem_cache_destroy
static inline void kmem_cache_destroy(struct kmem_cache *s)
{
	__bpf_slab_noop(s);
}
#endif

#ifndef kmem_cache_size
static inline unsigned int kmem_cache_size(struct kmem_cache *s)
{
	return s ? s->object_size : 0;
}
#endif

static inline size_t ksize(const void *p)
{
	__bpf_slab_noop(p);
	return 0;
}

#ifndef kmalloc_size_roundup
static inline size_t kmalloc_size_roundup(size_t size) { return size; }
#endif

#ifndef kvmalloc
static inline void *kvmalloc(size_t size, gfp_t flags)
{
	return __bpf_slab_null(size, flags);
}
#endif
#ifndef kvmalloc_node
static inline void *kvmalloc_node(size_t size, gfp_t flags, int node)
{
	return __bpf_slab_null(size, flags, node);
}
#endif
#ifndef kvzalloc
#define kvzalloc(size, flags)		kvmalloc((size), (flags) | __GFP_ZERO)
#endif
#ifndef kvzalloc_node
#define kvzalloc_node(size, flags, node) \
	kvmalloc_node((size), (flags) | __GFP_ZERO, (node))
#endif
#ifndef kvmalloc_array
static inline void *kvmalloc_array(size_t n, size_t size, gfp_t flags)
{
	return __bpf_slab_null(n, size, flags);
}
#endif
#ifndef kvmalloc_array_node
static inline void *kvmalloc_array_node(size_t n, size_t size, gfp_t flags,
					int node)
{
	return __bpf_slab_null(n, size, flags, node);
}
#endif
#ifndef kvcalloc
static inline void *kvcalloc(size_t n, size_t size, gfp_t flags)
{
	return __bpf_slab_null(n, size, flags);
}
#endif
#ifndef kvcalloc_node
static inline void *kvcalloc_node(size_t n, size_t size, gfp_t flags, int node)
{
	return __bpf_slab_null(n, size, flags, node);
}
#endif
#ifndef kvrealloc
static inline void *kvrealloc(const void *p, size_t size, gfp_t flags)
{
	return __bpf_slab_null(p, size, flags);
}
#endif
#ifndef kvrealloc_node
static inline void *kvrealloc_node(const void *p, size_t size, gfp_t flags,
				   int node)
{
	return __bpf_slab_null(p, size, flags, node);
}
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
