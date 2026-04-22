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

#define SLAB_HWCACHE_ALIGN	0x00002000U
#define SLAB_PANIC		0x00040000U
#define SLAB_ACCOUNT		0x04000000U

#define ZERO_SIZE_PTR		((void *)16)
#define ZERO_OR_NULL_PTR(x)	((unsigned long)(x) <= (unsigned long)ZERO_SIZE_PTR)

struct kmem_cache {
	unsigned int object_size;
	const char *name;
};

static inline void *kmalloc(size_t size, gfp_t flags)
{
	(void)size; (void)flags;
	return ((void *)0);
}

static inline void *kzalloc(size_t size, gfp_t flags)
{
	(void)size; (void)flags;
	return ((void *)0);
}

static inline void *kcalloc(size_t n, size_t size, gfp_t flags)
{
	(void)n; (void)size; (void)flags;
	return ((void *)0);
}

static inline void *krealloc(const void *p, size_t new_size, gfp_t flags)
{
	(void)p; (void)new_size; (void)flags;
	return ((void *)0);
}

static inline void *kmalloc_array(size_t n, size_t size, gfp_t flags)
{
	(void)n; (void)size; (void)flags;
	return ((void *)0);
}

static inline void *krealloc_array(void *p, size_t new_n, size_t new_size, gfp_t flags)
{
	(void)p; (void)new_n; (void)new_size; (void)flags;
	return ((void *)0);
}

static inline void kfree(const void *p) { (void)p; }
static inline void kfree_sensitive(const void *p) { (void)p; }
static inline void kvfree(const void *p) { (void)p; }

static inline void *kmem_cache_alloc(struct kmem_cache *s, gfp_t flags)
{
	(void)s; (void)flags;
	return ((void *)0);
}

static inline void kmem_cache_free(struct kmem_cache *s, void *p)
{
	(void)s; (void)p;
}

static inline size_t ksize(const void *p)
{
	(void)p;
	return 0;
}

static inline size_t __size_mul(size_t a, size_t b) { return a * b; }
#define size_mul(a, b) __size_mul(a, b)

#define __alloc_objs(KMALLOC, GFP, TYPE, COUNT) \
	((TYPE *)KMALLOC(size_mul(sizeof(TYPE), COUNT), GFP))

#define kmalloc_objs(P, COUNT, ...) \
	__alloc_objs(kmalloc, GFP_KERNEL, typeof(P), COUNT)
#define kzalloc_objs(P, COUNT, ...) \
	__alloc_objs(kzalloc, GFP_KERNEL, typeof(P), COUNT)

#endif /* _LINUX_SLAB_H */
