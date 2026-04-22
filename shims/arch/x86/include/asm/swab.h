/* BPF shim: uapi/asm/swab.h
 *
 * The kernel's x86 swab.h uses inline asm (bswap) which the BPF backend
 * rejects.  Use compiler builtins instead — clang supports these for BPF.
 */
#ifndef _ASM_X86_SWAB_H
#define _ASM_X86_SWAB_H

#include <linux/types.h>

static __always_inline __u32 __arch_swab32(__u32 val)
{
	return __builtin_bswap32(val);
}

static __always_inline __u64 __arch_swab64(__u64 val)
{
	return __builtin_bswap64(val);
}

#define __arch_swab32 __arch_swab32
#define __arch_swab64 __arch_swab64

#endif /* _ASM_X86_SWAB_H */
