// SPDX-License-Identifier: GPL-2.0-only
/*
 * khost.h — minimal host-side shim to compile isolated kernel lib/ functions
 * as ordinary userspace code under AddressSanitizer / UBSan.
 *
 * Force-included (-include khost.h) before a harness pulls in the real kernel
 * source. Unlike the BPF shim tree, this keeps real libc memcpy/memset/etc. so
 * the sanitizers instrument the genuine memory operations. Provides only the
 * kernel primitives the targeted functions need; extend as new targets are
 * added.
 */
#ifndef KHOST_H
#define KHOST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;
typedef u8 __u8; typedef u16 __u16; typedef u32 __u32; typedef u64 __u64;
typedef u16 __le16; typedef u32 __le32; typedef u64 __le64;
typedef u16 __be16; typedef u32 __be32; typedef u64 __be64;

#ifndef U32_MAX
#define U32_MAX ((u32)~0U)
#endif
#ifndef ULONG_MAX
#define ULONG_MAX (~0UL)
#endif

/* attributes / annotations that carry no meaning for a host build */
#define __maybe_unused __attribute__((unused))
#define __always_unused __attribute__((unused))
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#ifndef __attribute_const__
#define __attribute_const__ __attribute__((const))
#endif
#define __pure __attribute__((pure))
#define __init
#define __exit
#define __user
#define __force
#define __iomem
#define __percpu
#define notrace
#define asmlinkage
#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)
#define MODULE_LICENSE(x)
#define MODULE_AUTHOR(x)
#define MODULE_DESCRIPTION(x)
#define module_init(x)
#define module_exit(x)

/* diagnostics: record that a warn/bug fired so harnesses can treat it as a
 * finding, but never abort (we want to keep fuzzing). */
extern unsigned long khost_warn_count;
#define WARN(cond, ...)      ({ int __c = !!(cond); if (__c) khost_warn_count++; __c; })
#define WARN_ON(cond)        WARN(cond)
#define WARN_ONCE(cond, ...) WARN(cond)
#define WARN_ON_ONCE(cond)   WARN(cond)
#define BUG_ON(cond)         ((void)(cond))
#define BUG()                ((void)0)
#define pr_info(...)         ((void)0)
#define pr_warn(...)         ((void)0)
#define pr_err(...)          ((void)0)

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define BUILD_BUG_ON(cond) ((void)sizeof(char[1 - 2 * !!(cond)]))
#define BUILD_BUG_ON_MSG(cond, msg) BUILD_BUG_ON(cond)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* min/max/clamp — kernel semantics, simplified (no strict type checking) */
#define min(a, b)  ((a) < (b) ? (a) : (b))
#define max(a, b)  ((a) > (b) ? (a) : (b))
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define clamp(v, lo, hi) max((lo), min((v), (hi)))
#define swap(a, b) do { typeof(a) __t = (a); (a) = (b); (b) = __t; } while (0)

/* bit scans (kernel semantics: fls(0)==0, fls of MSB-set == bit index+1) */
static inline int fls(unsigned int x)  { return x ? 32 - __builtin_clz(x) : 0; }
static inline int fls64(u64 x)         { return x ? 64 - __builtin_clzll(x) : 0; }
static inline int __ffs(unsigned long x) { return __builtin_ctzl(x); }
static inline unsigned long __fls(unsigned long x) { return 63 - __builtin_clzl(x); }
/* ffs() is provided by libc <strings.h> with matching (1-indexed) semantics. */
#ifndef BITS_PER_LONG
#define BITS_PER_LONG 64
#endif
static inline unsigned int hweight32(u32 w) { return __builtin_popcount(w); }
static inline unsigned int hweight64(u64 w) { return __builtin_popcountll(w); }
static inline unsigned long fls_long(unsigned long l)
{
	return l ? (sizeof(l) == 4 ? (unsigned long)fls((unsigned int)l)
				   : (unsigned long)fls64(l)) : 0;
}
#define OPTIMIZER_HIDE_VAR(var) __asm__ __volatile__("" : "+r"(var))

/* do_div(n, base): set n = n / base, return the remainder. */
#define do_div(n, base) ({                     \
	uint32_t __base = (base);              \
	uint32_t __rem = (uint64_t)(n) % __base; \
	(n) = (uint64_t)(n) / __base;          \
	__rem;                                 \
})

#endif /* KHOST_H */
