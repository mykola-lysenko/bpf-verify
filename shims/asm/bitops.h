/* BPF shim: asm/bitops.h
 * x86 bitops.h uses bsf/bsr/btc inline asm not valid in BPF.
 * Replace with __builtin_ctz/__builtin_clz equivalents.
 * The real bitops.h requires being included via linux/bitops.h,
 * so we keep that guard check.
 */
#ifndef _ASM_X86_BITOPS_H
#define _ASM_X86_BITOPS_H

#ifndef _LINUX_BITOPS_H
#error only <linux/bitops.h> can be included directly
#endif

#include <linux/compiler.h>
#include <asm/alternative.h>
#include <asm/rmwcc.h>
#include <asm/barrier.h>

#if BITS_PER_LONG == 32
# define _BITOPS_LONG_SHIFT 5
#elif BITS_PER_LONG == 64
# define _BITOPS_LONG_SHIFT 6
#else
# error "Unexpected BITS_PER_LONG"
#endif

#define BIT_64(n)	(U64_C(1) << (n))

/* Atomic bit operations - use asm-generic versions */
#include <asm-generic/bitops/atomic.h>
#include <asm-generic/bitops/non-atomic.h>
#include <asm-generic/bitops/lock.h>

/* __ffs: find first set bit (undefined if word == 0)
 * Pure-C binary search — __builtin_ctz generates CTTZ (opcode 191),
 * which this LLVM version does not support for BPF. */
static __always_inline unsigned long __ffs(unsigned long word)
{
	unsigned long r = 0;
#if BITS_PER_LONG == 64
	if (!(word & 0xffffffffUL)) { r += 32; word >>= 32; }
#endif
	if (!(word & 0xffffU))     { r += 16; word >>= 16; }
	if (!(word & 0xffU))       { r +=  8; word >>=  8; }
	if (!(word & 0xfU))        { r +=  4; word >>=  4; }
	if (!(word & 0x3U))        { r +=  2; word >>=  2; }
	if (!(word & 0x1U))        { r +=  1; }
	return r;
}

/* ffz: find first zero bit (undefined if word == ~0UL) */
static __always_inline unsigned long ffz(unsigned long word)
{
	return __ffs(~word);
}

/* __fls: find last set bit (undefined if word == 0)
 * Pure-C binary search — __builtin_clz generates CTLZ (opcode 192),
 * which this LLVM version does not support for BPF. */
static __always_inline unsigned long __fls(unsigned long word)
{
	unsigned long r = BITS_PER_LONG - 1;
#if BITS_PER_LONG == 64
	if (!(word & (~0UL << 32))) { r -= 32; word <<= 32; }
#endif
	if (!(word & (~0UL << (BITS_PER_LONG - 16)))) { r -= 16; word <<= 16; }
	if (!(word & (~0UL << (BITS_PER_LONG -  8)))) { r -=  8; word <<=  8; }
	if (!(word & (~0UL << (BITS_PER_LONG -  4)))) { r -=  4; word <<=  4; }
	if (!(word & (~0UL << (BITS_PER_LONG -  2)))) { r -=  2; word <<=  2; }
	if (!(word & (~0UL << (BITS_PER_LONG -  1)))) { r -=  1; }
	return r;
}

/* ffs: find first set bit, 1-indexed, returns 0 if none */
static __always_inline int ffs(int x)
{
	if (!x) return 0;
	return (int)__ffs((unsigned long)(unsigned int)x) + 1;
}

/* fls: find last set bit, 1-indexed, returns 0 if none */
static __always_inline int fls(unsigned int x)
{
	if (!x) return 0;
	return (int)__fls((unsigned long)x) + 1;
}

/* fls64: find last set bit in 64-bit word, 1-indexed, returns 0 if none */
static __always_inline int fls64(__u64 x)
{
	if (!x) return 0;
	return (int)__fls((unsigned long)x) + 1;
}

/* hweight variants - use builtins */
#include <asm-generic/bitops/hweight.h>
#include <asm-generic/bitops/sched.h>
#include <asm-generic/bitops/const_hweight.h>
#include <asm-generic/bitops/le.h>
#include <asm-generic/bitops/ext2-atomic.h>

#endif /* _ASM_X86_BITOPS_H */
