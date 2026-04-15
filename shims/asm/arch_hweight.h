/* BPF shim: asm/arch_hweight.h
 * Replace x86 popcnt inline asm (not valid in BPF) with __builtin_popcount.
 */
#ifndef _ASM_X86_HWEIGHT_H
#define _ASM_X86_HWEIGHT_H

static __always_inline unsigned int __arch_hweight32(unsigned int w)
{
	return __builtin_popcount(w);
}
static inline unsigned int __arch_hweight16(unsigned int w)
{
	return __builtin_popcount(w & 0xffff);
}
static inline unsigned int __arch_hweight8(unsigned int w)
{
	return __builtin_popcount(w & 0xff);
}
static __always_inline unsigned long __arch_hweight64(__u64 w)
{
	return __builtin_popcountll(w);
}

#endif /* _ASM_X86_HWEIGHT_H */
