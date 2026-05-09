/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: asm/page_64.h
 *
 * The real x86 header defines page helpers with alternative/rep inline asm,
 * which cannot be compiled for the BPF target.  Keep the page geometry from
 * the real type headers and provide C equivalents for the helpers that the
 * harnesses may include.
 */
#ifndef _ASM_X86_PAGE_64_H
#define _ASM_X86_PAGE_64_H

#include <vdso/page.h>
#include <asm/page_64_types.h>

#if !defined(__ASSEMBLY__) && !defined(__ASSEMBLER__)
#include <linux/types.h>

/* Used by __PAGE_OFFSET and related constants from asm/page_64_types.h. */
extern unsigned long page_offset_base;
extern unsigned long vmalloc_base;
extern unsigned long vmemmap_base;

static inline void clear_pages(void *addr, unsigned int npages)
{
	unsigned int i;
	char *page = addr;

	for (i = 0; i < npages; i++)
		__builtin_memset(page + i * PAGE_SIZE, 0, PAGE_SIZE);
}
#define clear_pages clear_pages

static inline void clear_page(void *page)
{
	__builtin_memset(page, 0, PAGE_SIZE);
}

static inline void copy_page(void *to, void *from)
{
	__builtin_memcpy(to, from, PAGE_SIZE);
}

static __always_inline unsigned long task_size_max(void)
{
	return (1UL << 47) - PAGE_SIZE;
}

#endif /* !__ASSEMBLY__ && !__ASSEMBLER__ */
#endif /* _ASM_X86_PAGE_64_H */
