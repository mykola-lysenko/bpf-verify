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

#define __BPF_DEFINE_MEMSET_WORD(name, type)		\
static inline void *name(type *s, type v, size_t n)	\
{							\
	type *p = s;					\
							\
	while (n--)					\
		*p++ = v;				\
	return s;					\
}

#ifndef __HAVE_ARCH_MEMSET16
#define __HAVE_ARCH_MEMSET16
__BPF_DEFINE_MEMSET_WORD(memset16, uint16_t)
#endif
#ifndef __HAVE_ARCH_MEMSET32
#define __HAVE_ARCH_MEMSET32
__BPF_DEFINE_MEMSET_WORD(memset32, uint32_t)
#endif
#ifndef __HAVE_ARCH_MEMSET64
#define __HAVE_ARCH_MEMSET64
__BPF_DEFINE_MEMSET_WORD(memset64, uint64_t)
#endif

#undef __BPF_DEFINE_MEMSET_WORD

#endif /* __BPF_ASM_X86_STRING_64_SHIM_H */
