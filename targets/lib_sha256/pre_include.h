/* __DISABLE_EXPORTS: skip arch-specific sha256.h (which pulls in the
 * x86 __bpf_sha256_transform extern) and instead use sha256_blocks_generic.
 * Also skips the module-export wrappers (lines 276-512 of sha256.c). */
#define __DISABLE_EXPORTS
#define sha256_finup_2x __attribute__((internal_linkage)) sha256_finup_2x
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
/* Override sha256_blocks_generic to use a static W[64] array (.data section)
 * instead of a stack-allocated one.  The original allocates W[64] = 256 bytes
 * on the BPF stack, which combined with the caller frames exceeds the 512-byte
 * BPF call-chain stack limit.  Moving W to .data avoids the overflow.
 * We rename the original to __bpf_sha256_blocks_orig (suppressed via the macro)
 * and provide our own wrapper. */
#define sha256_blocks_generic __bpf_sha256_blocks_orig
