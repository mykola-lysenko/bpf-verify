/* BPF shim: asm/string_64.h
 * x86 string_64.h uses rep/stos inline asm not valid in BPF.
 * Provide C implementations of the extended memset/memcpy variants.
 */
#ifndef _ASM_X86_STRING_64_H
#define _ASM_X86_STRING_64_H

#include <linux/types.h>

/* Standard memcpy/memset/memmove declarations.
 * Guard with __HAVE_ARCH_* so that callers who provide their own
 * static-inline definitions (e.g. lz4_decompress) don't get a conflict. */
#ifndef __HAVE_ARCH_MEMCPY
#define __HAVE_ARCH_MEMCPY 1
extern void *memcpy(void *to, const void *from, size_t len);
#endif
#ifndef __HAVE_ARCH_MEMSET
#define __HAVE_ARCH_MEMSET
extern void *memset(void *s, int c, size_t n);
#endif
#ifndef __HAVE_ARCH_MEMMOVE
#define __HAVE_ARCH_MEMMOVE
extern void *memmove(void *dest, const void *src, size_t n);
#endif
extern int memcmp(const void *s1, const void *s2, size_t n);

/* Extended memset variants - replace inline asm with C loops */
#define __HAVE_ARCH_MEMSET16
static inline void *memset16(uint16_t *s, uint16_t v, size_t n)
{
	uint16_t *p = s;
	while (n--)
		*p++ = v;
	return s;
}

#define __HAVE_ARCH_MEMSET32
static inline void *memset32(uint32_t *s, uint32_t v, size_t n)
{
	uint32_t *p = s;
	while (n--)
		*p++ = v;
	return s;
}

#define __HAVE_ARCH_MEMSET64
static inline void *memset64(uint64_t *s, uint64_t v, size_t n)
{
	uint64_t *p = s;
	while (n--)
		*p++ = v;
	return s;
}

#endif /* _ASM_X86_STRING_64_H */
