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
#define __bpf_gfp_null(...)		((void *)0)
#define __bpf_gfp_alloc_stub(type, name, ...)		\
	static inline type name(__VA_ARGS__)		\
	{						\
		return (type)__bpf_gfp_null();		\
	}
#define __bpf_gfp_free_stub(name, ...)			\
	static inline void name(__VA_ARGS__) { }

/* Minimal allocation stubs - BPF programs don't actually allocate memory. */
__bpf_gfp_alloc_stub(struct page *, alloc_pages,
		     gfp_t gfp, unsigned int order)
__bpf_gfp_alloc_stub(struct page *, alloc_pages_node,
		     int nid, gfp_t gfp, unsigned int order)
__bpf_gfp_free_stub(__free_pages, struct page *page, unsigned int order)
__bpf_gfp_alloc_stub(void *, alloc_pages_exact, size_t size, gfp_t gfp)
__bpf_gfp_free_stub(free_pages_exact, void *addr, size_t size)
__bpf_gfp_alloc_stub(struct folio *, folio_alloc,
		     gfp_t gfp, unsigned int order)
__bpf_gfp_free_stub(folio_put, struct folio *folio)

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
#define alloc_tag_save(_tag)		__bpf_gfp_null(_tag)
#define alloc_tag_restore(_tag, _old)	__bpf_gfp_noop(_tag, _old)
#endif

#endif /* __LINUX_GFP_H */
