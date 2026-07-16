/* SHA-512 (lib/crypto/sha512.c). Mirrors lib_sha256: -std=gnu11 (the source
 * uses C99 for-loop declarations), __DISABLE_EXPORTS to skip the arch header
 * (x86 blocks extern) and the module-export wrappers, and inline mem* to avoid
 * extern BTF references. Unlike sha256, sha512_block_generic keeps its W[16]
 * (128 bytes) internal, so no static-W workaround is needed. We drive
 * sha512_blocks_generic directly (whole 128-byte blocks) to stay clear of the
 * streaming __sha512_update partial-buffer path -- the same buflen pattern that
 * is a documented verifier boundary for poly1305. */
#define __DISABLE_EXPORTS
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
