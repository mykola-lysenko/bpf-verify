/* BPF has no 128-bit integer support, so use the generic 32-bit clmul path. */
#undef CONFIG_ARCH_SUPPORTS_INT128
#define _LINUX_STRING_H_
#include <linux/types.h>
#include <linux/stddef.h>
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
static inline void *memcpy(void *dst, const void *src, __kernel_size_t n)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    __kernel_size_t i;
    for (i = 0; i < n; i++) d[i] = s[i];
    return dst;
}
static inline void *memset(void *dst, int c, __kernel_size_t n)
{
    unsigned char *d = dst;
    __kernel_size_t i;
    for (i = 0; i < n; i++) d[i] = (unsigned char)c;
    return dst;
}
#define memzero_explicit(p, n) memset((p), 0, (n))
/* clang 22's BPF backend leaves the out-pointer argument in r0 when this
 * static void helper stays out-of-line; the verifier then rejects the
 * (dead) return value with "cannot return stack pointer to the caller".
 * Force it inline. The attribute on this forward declaration merges into
 * the definition in gf128hash.c. */
struct polyval_elem;
static void polyval_mul_generic(struct polyval_elem *a,
                                const struct polyval_elem *b)
    __attribute__((always_inline));
