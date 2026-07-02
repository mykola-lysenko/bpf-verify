/* Stub strlen and hex_to_bin to avoid extern BTF references. */
static inline __kernel_size_t strlen(const char *s)
{
    __kernel_size_t n = 0;
    while (s[n]) n++;
    return n;
}
static inline int hex_to_bin(unsigned char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}
/* strnlen: string.c defines it but it may generate an extern BTF reference
 * when string.c is compiled as a separate translation unit. Provide an
 * always_inline version here so net_utils.c uses this definition directly. */
static __always_inline __kernel_size_t strnlen(const char *s, __kernel_size_t maxlen)
{
    __kernel_size_t n = 0;
    while (n < maxlen && s[n]) n++;
    return n;
}
