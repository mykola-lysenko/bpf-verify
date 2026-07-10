/* kstrtox.c uses ULLONG_MAX and INT_MAX but BPF -nostdinc omits limits.h. */
#ifndef ULLONG_MAX
#define ULLONG_MAX (~0ULL)
#endif
#ifndef LLONG_MAX
#define LLONG_MAX  ((long long)(ULLONG_MAX >> 1))
#endif
#ifndef LLONG_MIN
#define LLONG_MIN  (-LLONG_MAX - 1)
#endif
#ifndef INT_MAX
#define INT_MAX    ((int)(~0U >> 1))
#endif
#ifndef INT_MIN
#define INT_MIN    (-INT_MAX - 1)
#endif
#ifndef UINT_MAX
#define UINT_MAX   (~0U)
#endif
/* min() is used by kstrtox.c but may not be defined yet when ctype.c is
 * included. Provide a safe fallback. */
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
/* kstrtox.c calls check_mul_overflow() but does not include
 * linux/overflow.h itself; in this stripped-down include environment
 * nothing pulls it in transitively, so the implicit declaration becomes an
 * unresolved extern that libbpf rejects at load time. The real macro is no
 * help either: __builtin_mul_overflow on u64 lowers to the 128-bit __multi3
 * libcall, which the BPF backend cannot emit. Include the header so its
 * guard blocks any later inclusion, then override the macro (both kstrtox
 * call sites are u64 * u64). The overflow test computes the product's high
 * word from 32-bit limbs: a divide-back check (*d / a != b) is recognized
 * by LLVM and canonicalized straight back into umul.with.overflow. */
#include <linux/overflow.h>
static inline int __bpf_check_mul_overflow_u64(unsigned long long a,
                                               unsigned long long b,
                                               unsigned long long *d)
{
    unsigned long long a_lo = a & 0xffffffffULL, a_hi = a >> 32;
    unsigned long long b_lo = b & 0xffffffffULL, b_hi = b >> 32;
    unsigned long long lo_lo = a_lo * b_lo;
    unsigned long long mid1 = a_lo * b_hi;
    unsigned long long mid2 = a_hi * b_lo;
    unsigned long long t = (lo_lo >> 32) + (mid1 & 0xffffffffULL)
                                         + (mid2 & 0xffffffffULL);
    unsigned long long hi = a_hi * b_hi + (mid1 >> 32) + (mid2 >> 32)
                                        + (t >> 32);
    *d = a * b;
    return hi != 0;
}
#undef check_mul_overflow
#define check_mul_overflow(a, b, d) __bpf_check_mul_overflow_u64((a), (b), (d))
