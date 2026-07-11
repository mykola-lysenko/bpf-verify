/* Provide memcpy and memset as static inline to avoid extern BTF references. */
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

/* Force the exported encoders inline. As out-of-line BPF subprograms they write
 * into the caller's stack buffer (the `data` cursor), which the verifier
 * rejects across frames ("cannot write into caller frame"). Inlined, the writes
 * land in the harness's own frame and their bounded loops verify normally. The
 * attribute on these forward declarations merges into the definitions in the
 * source. */
unsigned char *asn1_encode_integer(unsigned char *data, const unsigned char *end_data, s64 integer) __attribute__((always_inline));
unsigned char *asn1_encode_oid(unsigned char *data, const unsigned char *end_data, u32 oid[], int oid_len) __attribute__((always_inline));
unsigned char *asn1_encode_boolean(unsigned char *data, const unsigned char *end_data, _Bool val) __attribute__((always_inline));
