/* Stub __kmalloc to avoid extern BTF references.
 * textsearch.h is included directly (mm_types.h shim allows it). */
static inline void *__kmalloc(__kernel_size_t size, unsigned int flags)
    { (void)size; (void)flags; return (void *)0; }
static inline void *memcpy(void *dst, const void *src, __kernel_size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    __kernel_size_t i;
    for (i = 0; i < n; i++) d[i] = s[i];
    return dst;
}
