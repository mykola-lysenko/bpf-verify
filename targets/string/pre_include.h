/* Redefine __builtin_memcpy as a byte-copy loop.
 * string.c:265 (strlcat) calls __builtin_memcpy with a variable size;
 * the BPF backend rejects variable-size __builtin_memcpy.
 * A simple loop is BPF-safe and semantically equivalent. */
static __inline__ void *__bpf_memcpy_loop(void *dst, const void *src, __SIZE_TYPE__ n)
{{
    char *d = (char *)dst;
    const char *s = (const char *)src;
    while (n--) *d++ = *s++;
    return dst;
}}
#define __builtin_memcpy __bpf_memcpy_loop
/* Also provide memcpy as a static inline so libbpf can find BTF for it.
 * string.c calls memcpy in several places; without a definition, libbpf
 * fails to load the BPF object (-2 ENOENT for extern 'memcpy'). */
static __inline__ void *memcpy(void *dst, const void *src, __SIZE_TYPE__ n)
{{
    return __bpf_memcpy_loop(dst, src, n);
}}
