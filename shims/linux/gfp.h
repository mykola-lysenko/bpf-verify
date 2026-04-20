/* BPF shim: linux/gfp.h
 * gfp.h includes mmzone.h which pulls in mm_types.h with BPF-incompatible
 * constructs. For BPF verification we only need gfp_t and GFP_* flags.
 */
#ifndef __LINUX_GFP_H
#define __LINUX_GFP_H

#include <linux/gfp_types.h>

/* Forward declarations for types used in function signatures */
struct page;
struct folio;
struct zone;
struct zonelist;
struct mem_cgroup;

/* Minimal allocation stubs - BPF programs don't actually allocate memory */
static inline struct page *alloc_pages(gfp_t gfp, unsigned int order) { return (void *)0; }
static inline void __free_pages(struct page *page, unsigned int order) {}
static inline struct folio *folio_alloc(gfp_t gfp, unsigned int order) { return (void *)0; }
static inline void folio_put(struct folio *folio) {}

#define alloc_page(gfp)alloc_pages(gfp, 0)
#define __get_free_pages(gfp, order)((unsigned long)alloc_pages(gfp, order))
#define __get_free_page(gfp)__get_free_pages(gfp, 0)
#define get_zeroed_page(gfp)__get_free_pages((gfp)|__GFP_ZERO, 0)
#define free_pages(addr, order)do {} while (0)
#define free_page(addr)free_pages(addr, 0)



/* Helper macro to select default GFP flags when none are specified */
#define __default_gfp(a, b, ...) b
#define default_gfp(...) __default_gfp(,##__VA_ARGS__, GFP_KERNEL)
/* alloc_tag stubs - normally in sched.h but we block sched.h */
struct alloc_tag;
#ifndef alloc_tag_save
#define alloc_tag_save(_tag)         NULL
#define alloc_tag_restore(_tag, _old) do {} while (0)
#endif
#endif /* __LINUX_GFP_H */
