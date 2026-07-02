/* Block zstd_deps.h's ZSTD_DEPS_COMMON section so our ZSTD_mem* overrides
 * take effect. The section guard is ZSTD_DEPS_COMMON (not ZSTD_DEPS_H).
 * We define it here to prevent the __builtin_memset/memcpy/memmove macros
 * from being defined. We also include linux/limits.h and linux/stddef.h
 * that zstd_deps.h would normally include.
 * NOTE: Do NOT redefine size_t or U8/U16/etc -- linux/types.h already defines them. */
#include <linux/limits.h>
#include <linux/stddef.h>
#define ZSTD_DEPS_COMMON  /* Block the __builtin_mem* macros in zstd_deps.h */
/* Override ZSTD_memset/ZSTD_memcpy/ZSTD_memmove with loop-based macros.
 * __builtin_memset/memcpy/memmove with variable sizes are rejected by the BPF
 * backend. Use loop-based implementations instead. */
static __always_inline void *__bpf_memcpy(void *d, const void *s, __kernel_size_t n)
{{
    char *dd = (char *)d; const char *ss = (const char *)s;
    while (n--) *dd++ = *ss++; return d;
}}
static __always_inline void *__bpf_memmove(void *d, const void *s, __kernel_size_t n)
{{
    char *dd = (char *)d; const char *ss = (const char *)s;
    if (dd < ss) {{ while (n--) *dd++ = *ss++; }}
    else {{ dd += n; ss += n; while (n--) *--dd = *--ss; }}
    return d;
}}
static __always_inline void *__bpf_memset(void *d, int c, __kernel_size_t n)
{{
    char *dd = (char *)d; while (n--) *dd++ = (char)c; return d;
}}
#define ZSTD_memcpy(d,s,n) __bpf_memcpy((d),(s),(n))
#define ZSTD_memmove(d,s,n) __bpf_memmove((d),(s),(n))
#define ZSTD_memset(d,s,n) __bpf_memset((d),(s),(n))
/* Override FSE_ctz to avoid __builtin_ctz (opcode 191, not supported by BPF backend).
 * entropy_common.c defines FSE_ctz as static but uses __builtin_ctz when __GNUC__ >= 3.
 * We redefine it as a macro that uses a software loop instead. */
#define __GNUC__ 2  /* Force software fallback in FSE_ctz */
/* Stub for ERR_getErrorString (defined in error_private.c, a different TU).
 * libbpf rejects BPF objects with unresolved extern BTF references.
 * Provide a static inline stub so the reference is resolved in this TU. */
#define ERR_getErrorString __bpf_ERR_getErrorString
static __always_inline const char* __bpf_ERR_getErrorString(unsigned int code)
{ (void)code; return ""; }
/* Forward declarations with internal_linkage for all >5-arg non-static
 * functions in entropy_common.c. */
__attribute__((internal_linkage))
size_t FSE_readNCount_bmi2(short *normalizedCounter, unsigned *maxSVPtr,
    unsigned *tableLogPtr, const void *headerBuffer, size_t hbSize, int bmi2);
__attribute__((internal_linkage))
size_t HUF_readStats(unsigned char *huffWeight, size_t hwSize,
    unsigned int *rankStats, unsigned int *nbSymbolsPtr,
    unsigned int *tableLogPtr, const void *src, size_t srcSize);
__attribute__((internal_linkage))
size_t HUF_readStats_wksp(unsigned char *huffWeight, size_t hwSize,
    unsigned int *rankStats, unsigned int *nbSymbolsPtr,
    unsigned int *tableLogPtr, const void *src, size_t srcSize,
    void *workSpace, size_t wkspSize, int bmi2);
