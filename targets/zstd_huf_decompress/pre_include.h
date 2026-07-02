/* Block zstd_deps.h's ZSTD_DEPS_COMMON section (same approach as entropy_common). */
#include <linux/limits.h>
#include <linux/stddef.h>
#define ZSTD_DEPS_COMMON
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
/* Override __GNUC__ to force software fallbacks for __builtin_ctz/__builtin_clz
 * (opcodes 191/192, not supported by BPF backend). */
#define __GNUC__ 2
/* HUF_DTable is typedef U32 in huf.h */
typedef unsigned int HUF_DTable;
/* Cross-TU stubs: HUF_readStats_wksp and HUF_readStats are defined in
 * entropy_common.c (a different TU). internal_linkage forward decls don't
 * work for cross-TU functions (the definition must be in the same TU).
 * Use macro rename + static inline stub instead. */
#define HUF_readStats_wksp __bpf_HUF_readStats_wksp
static __always_inline size_t __bpf_HUF_readStats_wksp(
    unsigned char *huffWeight, size_t hwSize,
    unsigned int *rankStats, unsigned int *nbSymbolsPtr,
    unsigned int *tableLogPtr, const void *src, size_t srcSize,
    void *workSpace, size_t wkspSize, int bmi2)
{{ return 0; }}
#define HUF_readStats __bpf_HUF_readStats
static __always_inline size_t __bpf_HUF_readStats(
    unsigned char *huffWeight, size_t hwSize,
    unsigned int *rankStats, unsigned int *nbSymbolsPtr,
    unsigned int *tableLogPtr, const void *src, size_t srcSize)
{{ return 0; }}
/* Forward declarations with internal_linkage for all >5-arg non-static
 * functions DEFINED in huf_decompress.c itself. */
__attribute__((internal_linkage))
size_t HUF_readDTableX1_wksp(HUF_DTable *DTable, const void *src,
    size_t srcSize, void *workSpace, size_t wkspSize, int flags);
__attribute__((internal_linkage))
size_t HUF_readDTableX2_wksp(HUF_DTable *DTable, const void *src,
    size_t srcSize, void *workSpace, size_t wkspSize, int flags);
__attribute__((internal_linkage))
size_t HUF_decompress1X1_DCtx_wksp(HUF_DTable *DCtx, void *dst, size_t dstSize,
    const void *cSrc, size_t cSrcSize, void *workSpace, size_t wkspSize, int flags);
__attribute__((internal_linkage))
size_t HUF_decompress1X2_DCtx_wksp(HUF_DTable *DCtx, void *dst, size_t dstSize,
    const void *cSrc, size_t cSrcSize, void *workSpace, size_t wkspSize, int flags);
__attribute__((internal_linkage))
size_t HUF_decompress4X_hufOnly_wksp(HUF_DTable *dctx, void *dst,
    size_t dstSize, const void *cSrc, size_t cSrcSize,
    void *workSpace, size_t wkspSize, int flags);
__attribute__((internal_linkage))
size_t HUF_decompress1X_DCtx_wksp(HUF_DTable *dctx, void *dst, size_t dstSize,
    const void *cSrc, size_t cSrcSize, void *workSpace, size_t wkspSize, int flags);
__attribute__((internal_linkage))
size_t HUF_decompress1X_usingDTable(void *dst, size_t maxDstSize,
    const void *cSrc, size_t cSrcSize, const HUF_DTable *DTable, int flags);
__attribute__((internal_linkage))
size_t HUF_decompress4X_usingDTable(void *dst, size_t maxDstSize,
    const void *cSrc, size_t cSrcSize, const HUF_DTable *DTable, int flags);
__attribute__((internal_linkage))
size_t HUF_decompress4X1_usingDTable_internal_bmi2(void *dst, size_t dstSize,
    void const *cSrc, size_t cSrcSize, const HUF_DTable *DTable);
__attribute__((internal_linkage))
size_t HUF_decompress4X1_usingDTable_internal_default(void *dst, size_t dstSize,
    void const *cSrc, size_t cSrcSize, const HUF_DTable *DTable);
__attribute__((internal_linkage))
size_t HUF_decompress4X2_usingDTable_internal_bmi2(void *dst, size_t dstSize,
    void const *cSrc, size_t cSrcSize, const HUF_DTable *DTable);
__attribute__((internal_linkage))
size_t HUF_decompress4X2_usingDTable_internal_default(void *dst, size_t dstSize,
    void const *cSrc, size_t cSrcSize, const HUF_DTable *DTable);
