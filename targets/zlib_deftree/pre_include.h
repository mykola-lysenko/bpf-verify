/* Suppress the extern memcpy declaration in linux/string.h and
 * provide a static inline implementation instead. */
#define __HAVE_ARCH_MEMCPY
static inline void *memcpy(void *dst, const void *src, __kernel_size_t n)
{{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    __kernel_size_t i;
    for (i = 0; i < n; i++) d[i] = s[i];
    return dst;
}}
