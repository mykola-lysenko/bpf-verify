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

/* __ffs: find first set bit (undefined if word == 0) */
static __always_inline unsigned long __ffs(unsigned long word)
{
	return __builtin_ctzl(word);
}

/* ffz: find first zero bit (undefined if word == ~0) */
static __always_inline unsigned long ffz(unsigned long word)
{
	return __builtin_ctzl(~word);
}

/* __fls: find last set bit (undefined if word == 0) */
static __always_inline unsigned long __fls(unsigned long word)
{
	return (sizeof(word) * 8 - 1) - __builtin_clzl(word);
}

/* ffs: find first set bit, returns 0 if none */
static __always_inline int ffs(int x)
{
	return __builtin_ffs(x);
}

/* fls: find last set bit, returns 0 if none */
static __always_inline int fls(unsigned int x)
{
	return x ? (32 - __builtin_clz(x)) : 0;
}

/* fls64: find last set bit in 64-bit word */
static __always_inline int fls64(__u64 x)
{
	return x ? (64 - __builtin_clzll(x)) : 0;
}

/* hweight variants - use builtins */
#include <asm-generic/bitops/hweight.h>
#include <asm-generic/bitops/sched.h>
#include <asm-generic/bitops/const_hweight.h>
#include <asm-generic/bitops/le.h>
#include <asm-generic/bitops/ext2-atomic.h>

#endif /* _ASM_X86_BITOPS_H */
