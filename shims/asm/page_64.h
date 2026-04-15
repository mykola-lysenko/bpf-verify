/* BPF shim: asm/page_64.h
 * x86 page_64.h uses clear_page/copy_page inline asm not valid in BPF.
 * Provide stubs for the page operations.
 */
#ifndef _ASM_X86_PAGE_64_H
#define _ASM_X86_PAGE_64_H

#include <asm/page_64_types.h>

#ifndef __ASSEMBLY__

#include <linux/types.h>

/* Page clearing/copying stubs - not used in lib/ targets */
static inline void clear_page(void *page)
{
	__builtin_memset(page, 0, 4096);
}

static inline void copy_page(void *to, void *from)
{
	__builtin_memcpy(to, from, 4096);
}

/* virt_to_page stub */
struct page;
#define virt_to_page(x)		((struct page *)0)
#define page_to_virt(x)		((void *)0)

#endif /* !__ASSEMBLY__ */

#endif /* _ASM_X86_PAGE_64_H */
