/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BPF_ASM_X86_STRING_64_SHIM_H
#define __BPF_ASM_X86_STRING_64_SHIM_H

/*
 * The real x86 header provides the standard string declarations, but its
 * memset16/32/64 implementations use rep stos inline asm.  Pretend KMSAN is
 * enabled while including it so those asm helpers are skipped, then provide
 * BPF-safe C replacements below.
 */
#ifndef CONFIG_KMSAN
#define CONFIG_KMSAN
#define __BPF_STRING_64_DEFINED_CONFIG_KMSAN
#endif

#include_next <asm/string_64.h>

#ifdef __BPF_STRING_64_DEFINED_CONFIG_KMSAN
#undef CONFIG_KMSAN
#undef __BPF_STRING_64_DEFINED_CONFIG_KMSAN
#endif

#ifndef __HAVE_ARCH_MEMSET16
#define __HAVE_ARCH_MEMSET16
static inline void *memset16(uint16_t *s, uint16_t v, size_t n)
{
	uint16_t *p = s;

	while (n--)
		*p++ = v;
	return s;
}
#endif

#ifndef __HAVE_ARCH_MEMSET32
#define __HAVE_ARCH_MEMSET32
static inline void *memset32(uint32_t *s, uint32_t v, size_t n)
{
	uint32_t *p = s;

	while (n--)
		*p++ = v;
	return s;
}
#endif

#ifndef __HAVE_ARCH_MEMSET64
#define __HAVE_ARCH_MEMSET64
static inline void *memset64(uint64_t *s, uint64_t v, size_t n)
{
	uint64_t *p = s;

	while (n--)
		*p++ = v;
	return s;
}
#endif

#endif /* __BPF_ASM_X86_STRING_64_SHIM_H */
