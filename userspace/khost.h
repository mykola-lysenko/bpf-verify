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
#include <errno.h>   /* ENOMEM, EBADMSG, EKEYREJECTED, ... for kernel returns */

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
#define __initconst
#define __initdata
#define __ro_after_init
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
#define pr_debug(...)        ((void)0)
#define pr_cont(...)         ((void)0)
#define pr_notice(...)       ((void)0)
#define pr_devel(...)        ((void)0)

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#ifndef fallthrough
#define fallthrough __attribute__((__fallthrough__))
#endif
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
#define ALIGN(x, a)     (((x) + (a) - 1) & ~((typeof(x))(a) - 1))
#define PTR_ALIGN(p, a) ((typeof(p))ALIGN((uintptr_t)(p), (a)))

/* strscpy(): faithful to the kernel contract -- copy up to count-1 bytes,
 * stopping at the source NUL, always NUL-terminate; returns the length copied
 * or -E2BIG on truncation. Reads src exactly as the kernel does, so an
 * out-of-bounds source read by a caller is reproduced (and caught by ASan). */
#ifndef E2BIG
#define E2BIG 7
#endif
static inline long strscpy(char *dst, const char *src, size_t count)
{
	size_t i;
	if (count == 0)
		return -E2BIG;
	for (i = 0; i < count - 1; i++) {
		dst[i] = src[i];
		if (src[i] == '\0')
			return (long)i;
	}
	dst[i] = '\0';
	return src[i] == '\0' ? (long)i : -E2BIG;
}

/* bit scans (kernel semantics: fls(0)==0, fls of MSB-set == bit index+1) */
static inline int fls(unsigned int x)  { return x ? 32 - __builtin_clz(x) : 0; }
static inline int fls64(u64 x)         { return x ? 64 - __builtin_clzll(x) : 0; }
static inline int __ffs(unsigned long x) { return __builtin_ctzl(x); }
static inline unsigned long __fls(unsigned long x) { return 63 - __builtin_clzl(x); }
static inline u64 rol64(u64 w, unsigned int s) { return (w << s) | (w >> (64 - s)); }
static inline u64 ror64(u64 w, unsigned int s) { return (w >> s) | (w << (64 - s)); }
static inline u32 rol32(u32 w, unsigned int s) { return (w << s) | (w >> (32 - s)); }
static inline u32 ror32(u32 w, unsigned int s) { return (w >> s) | (w << (32 - s)); }
/* Host is little-endian: the LE conversions are the identity. */
static inline u64 le64_to_cpu(u64 x) { return x; }
static inline u32 le32_to_cpu(u32 x) { return x; }
static inline u16 le16_to_cpu(u16 x) { return x; }
static inline u64 cpu_to_le64(u64 x) { return x; }
static inline u32 cpu_to_le32(u32 x) { return x; }
static inline u16 cpu_to_le16(u16 x) { return x; }
static inline u16 __swab16(u16 x) { return __builtin_bswap16(x); }
static inline u32 __swab32(u32 x) { return __builtin_bswap32(x); }
static inline u64 __swab64(u64 x) { return __builtin_bswap64(x); }
/* Big-endian conversions: byte-swap on a little-endian host. */
static inline u64 cpu_to_be64(u64 x) { return __builtin_bswap64(x); }
static inline u32 cpu_to_be32(u32 x) { return __builtin_bswap32(x); }
static inline u16 cpu_to_be16(u16 x) { return __builtin_bswap16(x); }
static inline u64 be64_to_cpu(u64 x) { return __builtin_bswap64(x); }
static inline u32 be32_to_cpu(u32 x) { return __builtin_bswap32(x); }
static inline u16 be16_to_cpu(u16 x) { return __builtin_bswap16(x); }
static inline void memzero_explicit(void *s, size_t n)
{
	memset(s, 0, n);
	__asm__ __volatile__("" : : "r"(s) : "memory");
}
static inline bool mem_is_zero(const void *p, size_t n)
{
	const unsigned char *b = p;
	for (size_t i = 0; i < n; i++)
		if (b[i])
			return false;
	return true;
}
/* In-place LE conversions: no-ops on a little-endian host. */
static inline void le64_to_cpus(void *p) { (void)p; }
static inline void le32_to_cpus(void *p) { (void)p; }
static inline void le16_to_cpus(void *p) { (void)p; }
#ifndef static_assert
#define static_assert(expr, ...) _Static_assert(expr, #expr)
#endif
/* ffs() is provided by libc <strings.h> with matching (1-indexed) semantics. */
#ifndef BITS_PER_LONG
#define BITS_PER_LONG 64
#endif

/* Config predicates: optional features off, x86-style capabilities on. */
#ifndef IS_ENABLED
#define IS_ENABLED(cfg) 0
#endif
#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS 1
#endif

/* slab: heap allocation maps to libc so ASan tracks it. GFP flags ignored. */
#define GFP_KERNEL 0
#define GFP_ATOMIC 0
#define __GFP_ZERO 0
#include <stdlib.h>
static inline void *kmalloc(size_t n, unsigned f)
{
	void *p = malloc(n ? n : 1);
	if (p && (f & __GFP_ZERO))
		memset(p, 0, n);
	return p;
}
static inline void *kzalloc(size_t n, unsigned f) { (void)f; return calloc(1, n ? n : 1); }
static inline void *kmalloc_array(size_t n, size_t sz, unsigned f) { (void)f; return calloc(n, sz); }
static inline void *kcalloc(size_t n, size_t sz, unsigned f) { (void)f; return calloc(n, sz); }
static inline void kfree(const void *p) { free((void *)p); }
static inline void kfree_sensitive(const void *p) { free((void *)p); }
#define kzalloc_obj(x)  kzalloc(sizeof(x), GFP_KERNEL)
#define kmalloc_obj(x)  kmalloc(sizeof(x), GFP_KERNEL)
#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif
/* linux/cleanup.h __free() scope guard, minimal form for the frees we use. */
static inline void __free_kfree_sensitive(void *pp) { kfree_sensitive(*(void **)pp); }
static inline void __free_kfree(void *pp) { kfree(*(void **)pp); }
#define __free(f) __attribute__((__cleanup__(__free_##f)))
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
