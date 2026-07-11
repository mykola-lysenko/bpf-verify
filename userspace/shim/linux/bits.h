#ifndef _SHIM_LINUX_BITS_H
#define _SHIM_LINUX_BITS_H

/* Minimal linux/bits.h: the kernel header pulls in linux/overflow.h (which
 * needs __must_check / compiler-diag machinery unavailable here). cnum only
 * needs the basic bit constructors, so provide those and stop the chain. */
#ifndef BITS_PER_LONG
#define BITS_PER_LONG 64
#endif
#ifndef BIT
#define BIT(n)      (1UL << (n))
#endif
#ifndef BIT_ULL
#define BIT_ULL(n)  (1ULL << (n))
#endif
#ifndef GENMASK
#define GENMASK(h, l) \
	(((~0UL) - (1UL << (l)) + 1) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#endif
#ifndef GENMASK_ULL
#define GENMASK_ULL(h, l) \
	(((~0ULL) - (1ULL << (l)) + 1) & (~0ULL >> (64 - 1 - (h))))
#endif

#endif
