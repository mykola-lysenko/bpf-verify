/* Provide memcpy and memset as static inline to avoid extern BTF references.
 * memcpy is used by hchacha_block_generic() in chacha-block-generic.c.
 * memset is used by chacha_zeroize_state() (via memzero_explicit). */
static inline void *memcpy(void *dst, const void *src, __kernel_size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    __kernel_size_t i;
    for (i = 0; i < n; i++) d[i] = s[i];
    return dst;
}
static inline void *memset(void *dst, int c, __kernel_size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    __kernel_size_t i;
    for (i = 0; i < n; i++) d[i] = (unsigned char)c;
    return dst;
}
