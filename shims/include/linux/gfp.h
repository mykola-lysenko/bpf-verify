/* BPF shim: linux/gfp.h
 * gfp.h includes mmzone.h which pulls in mm_types.h with BPF-incompatible
 * constructs. For BPF verification we only need gfp_t and GFP_* flags.
 */
#ifndef __LINUX_GFP_H
#define __LINUX_GFP_H

#include <linux/types.h>
#include <linux/gfp_types.h>

struct page;
struct folio;
struct zone;
struct zonelist;
struct mem_cgroup;

#define __bpf_gfp_noop(...)		do { } while (0)

/* Minimal allocation stubs - BPF programs don't actually allocate memory. */
static inline struct page *alloc_pages(gfp_t gfp, unsigned int order)
{
	__bpf_gfp_noop(gfp, order);
	return (void *)0;
}

static inline struct page *alloc_pages_node(int nid, gfp_t gfp,
					    unsigned int order)
{
	__bpf_gfp_noop(nid);
	return alloc_pages(gfp, order);
}

static inline void __free_pages(struct page *page, unsigned int order)
{
	__bpf_gfp_noop(page, order);
}

static inline void *alloc_pages_exact(size_t size, gfp_t gfp)
{
	__bpf_gfp_noop(size, gfp);
	return (void *)0;
}

static inline void free_pages_exact(void *addr, size_t size)
{
	__bpf_gfp_noop(addr, size);
}

static inline struct folio *folio_alloc(gfp_t gfp, unsigned int order)
{
	__bpf_gfp_noop(gfp, order);
	return (void *)0;
}

static inline void folio_put(struct folio *folio)
{
	__bpf_gfp_noop(folio);
}

#define alloc_page(gfp)			alloc_pages((gfp), 0)
#define __free_page(page)		__free_pages((page), 0)
#define __get_free_pages(gfp, order)	((unsigned long)alloc_pages((gfp), (order)))
#define __get_free_page(gfp)		__get_free_pages((gfp), 0)
#define get_zeroed_page(gfp)		__get_free_pages((gfp) | __GFP_ZERO, 0)
#define free_pages(addr, order)		__bpf_gfp_noop(addr, order)
#define free_page(addr)			free_pages((addr), 0)

/* Helper macro to select default GFP flags when none are specified */
#define __default_gfp(a, b, ...) b
#define default_gfp(...) __default_gfp(,##__VA_ARGS__, GFP_KERNEL)

/* Keep alloc-hook wrapped declarations compileable without scheduler state. */
#ifndef alloc_hooks
#define alloc_hooks(expr)		(expr)
#endif

/* alloc_tag stubs - normally in sched.h but we block sched.h */
struct alloc_tag;
#ifndef alloc_tag_save
#define alloc_tag_save(_tag)		((void *)0)
#define alloc_tag_restore(_tag, _old)	__bpf_gfp_noop(_tag, _old)
#endif

#endif /* __LINUX_GFP_H */
