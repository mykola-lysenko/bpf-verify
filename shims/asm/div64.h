/* BPF shim: asm/div64.h
 * x86 div64.h uses divl/mulq inline asm not valid in BPF.
 * For 64-bit BPF, use asm-generic/div64.h and provide C mul_u64_u64_div_u64.
 */
#ifndef _ASM_X86_DIV64_H
#define _ASM_X86_DIV64_H

/* We're always 64-bit in BPF, so skip the x86-32 path */
#include <asm-generic/div64.h>

/* Replace the inline asm mul+div with C equivalent */
static inline u64 mul_u64_u64_div_u64(u64 a, u64 mul, u64 div)
{
	/* Use __uint128_t to avoid overflow */
	return (u64)((__uint128_t)a * mul / div);
}
#define mul_u64_u64_div_u64 mul_u64_u64_div_u64

static inline u64 mul_u64_u32_div(u64 a, u32 mul, u32 div)
{
	return mul_u64_u64_div_u64(a, mul, div);
}
#define mul_u64_u32_div mul_u64_u32_div

#endif /* _ASM_X86_DIV64_H */
