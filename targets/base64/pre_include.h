/* Suppress extern strchr/memchr declarations from linux/string.h and
 * provide static inline implementations. The BPF backend lowers strchr
 * to memchr, so both stubs are required. */
#define __HAVE_ARCH_STRCHR
#define __HAVE_ARCH_MEMCHR
static inline char *strchr(const char *s, int c)
{{
    while (*s) {{
        if (*s == (char)c) return (char *)s;
        s++;
    }}
    return (void *)0;
}}
static inline void *memchr(const void *s, int c, __kernel_size_t n)
{{
    const unsigned char *p = (const unsigned char *)s;
    __kernel_size_t i;
    for (i = 0; i < n; i++)
        if (p[i] == (unsigned char)c) return (void *)(p + i);
    return (void *)0;
}}
