#define _LINUX_SORT_H
#define _LINUX_STRING_H_
#define sort(base, num, size, cmp, priv) do { } while (0)

#define __HAVE_ARCH_MEMMOVE
static __always_inline void *memmove(void *dst, const void *src, __kernel_size_t n)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    __kernel_size_t i;

    for (i = 0; i < 128; i++) {
        if (i >= n)
            break;
        d[i] = s[i];
    }

    return dst;
}

#pragma clang attribute push(__attribute__((internal_linkage)), apply_to=function)
