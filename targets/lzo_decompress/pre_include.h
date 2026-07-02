/* Provide memset as static inline to avoid extern BTF reference. */
static inline void *memset(void *dst, int c, __kernel_size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    __kernel_size_t i;
    for (i = 0; i < n; i++) d[i] = (unsigned char)c;
    return dst;
}
