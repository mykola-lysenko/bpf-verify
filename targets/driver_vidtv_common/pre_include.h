#define _LINUX_RATELIMIT_H
#define pr_err_ratelimited(fmt, ...) do { } while (0)

#define __HAVE_ARCH_MEMCPY
static __always_inline void *memcpy(void *dst, const void *src, __kernel_size_t n)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    __kernel_size_t i;

    for (i = 0; i < 64; i++) {
        if (i >= n)
            break;
        d[i] = s[i];
    }

    return dst;
}

#define __HAVE_ARCH_MEMSET
static __always_inline void *memset(void *dst, int c, __kernel_size_t n)
{
    unsigned char *d = dst;
    __kernel_size_t i;

    for (i = 0; i < 64; i++) {
        if (i >= n)
            break;
        d[i] = (unsigned char)c;
    }

    return dst;
}
