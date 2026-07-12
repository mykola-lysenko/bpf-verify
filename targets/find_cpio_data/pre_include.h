/* earlycpio's find_cpio_data() uses strlen() on the search path and memcmp()
 * to match names. Provide both as static inline so they don't become unresolved
 * externs that libbpf rejects. */
static inline __kernel_size_t strlen(const char *s)
{
    __kernel_size_t n = 0;
    while (s[n]) n++;
    return n;
}
static inline int memcmp(const void *a, const void *b, __kernel_size_t n)
{
    const unsigned char *pa = a, *pb = b;
    __kernel_size_t i;
    for (i = 0; i < n; i++) {
        if (pa[i] != pb[i])
            return (int)pa[i] - (int)pb[i];
    }
    return 0;
}
/* strscpy() expands to sized_strscpy(); find_cpio_data() uses it to copy the
 * matched record name into cd.name. Provide it inline (bounded by count) so it
 * doesn't become an unresolved extern that blocks the object load. */
static inline ssize_t sized_strscpy(char *dst, const char *src, __kernel_size_t count)
{
    __kernel_size_t i;
    if (count == 0)
        return -7 /* -E2BIG */;
    for (i = 0; i < count; i++) {
        dst[i] = src[i];
        if (src[i] == '\0')
            return (ssize_t)i;
    }
    dst[count - 1] = '\0';
    return -7 /* -E2BIG */;
}
