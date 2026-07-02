/* Use the generic SHA-1 implementation and avoid unresolved string/FIPS externs. */
#undef CONFIG_CRYPTO_LIB_SHA1_ARCH
#undef CONFIG_CRYPTO_FIPS
#define _LINUX_STRING_H_
#include <linux/types.h>
#include <linux/stddef.h>
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
static inline int memcmp(const void *a, const void *b, __kernel_size_t n)
{
    const unsigned char *p = a, *q = b;
    __kernel_size_t i;
    for (i = 0; i < n; i++) {
        if (p[i] != q[i]) return p[i] - q[i];
    }
    return 0;
}
#define memzero_explicit(p, n) memset((p), 0, (n))
