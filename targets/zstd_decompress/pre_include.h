/* Strategy: macro-rename all problematic functions BEFORE zstd_lib.h is included.
 * This ensures zstd_lib.h declares the renamed versions (not the originals).
 * Then provide static inline stubs for the renamed versions.
 * Problems:
 *   1. ZSTD_customMalloc/Free/Calloc take ZSTD_customMem by value.
 *   2. ZSTD_decompress_usingDict (7 args), ZSTD_decompress_usingDDict (6 args),
 *      ZSTD_decompressStream_simpleArgs (7 args) exceed the 5-arg BPF limit.
 *   3. ZSTD_createDCtx_advanced takes ZSTD_customMem by value.
 *   4. ZSTD_decompressBlock_internal (6 args), ZSTD_buildFSETable (9 args) are
 *      non-static cross-TU functions with too many args.
 *   5. ZSTD_decompressMultiFrame has 8 args and uses the internal_linkage
 *      static-subprogram path.
 *   6. ZSTD_findFrameSizeInfo/ZSTD_errorFrameSizeInfo return struct by value.
 *   7. ZSTD_memcpy/memset are __builtin_memcpy/__builtin_memset (BPF rejects). */
/* Step 0: Override __GNUC__ to force software fallback for __builtin_clz/__builtin_ctz
 * (BPF backend rejects CTLZ/CTTZ opcodes). */
#undef __GNUC__
#define __GNUC__ 2
/* Step 1: Apply internal_linkage to ALL functions declared/defined from this point.
 * Must come BEFORE zstd_lib.h so the declarations there also get internal_linkage.
 * This ensures the first declaration of every function has internal_linkage,
 * satisfying clang's requirement. */
#pragma clang attribute push(__attribute__((internal_linkage)), apply_to=function)
/* Step 2: Rename problematic functions before zstd_lib.h declares them. */
#define ZSTD_customMalloc __bpf_ZSTD_customMalloc
#define ZSTD_customFree __bpf_ZSTD_customFree
#define ZSTD_customCalloc __bpf_ZSTD_customCalloc
#define ZSTD_createDCtx_advanced __bpf_ZSTD_createDCtx_advanced
#define ZSTD_decompress_usingDict __bpf_ZSTD_decompress_usingDict
#define ZSTD_decompress_usingDDict __bpf_ZSTD_decompress_usingDDict
#define ZSTD_decompressStream_simpleArgs __bpf_ZSTD_decompressStream_simpleArgs
#define ZSTD_createDDict_advanced __bpf_ZSTD_createDDict_advanced
#define ZSTD_dParam_getBounds __bpf_ZSTD_dParam_getBounds
/* Step 3: Include zstd_lib.h. It will declare the renamed versions with internal_linkage. */
#include <linux/zstd_lib.h>
/* Step 4: NOTE: Do NOT provide stubs for __bpf_ZSTD_customMalloc/Free/Calloc here.
 * The rename macros above cause allocations.h (included from zstd_decompress.c)
 * to define them as MEM_STATIC (static inline). Providing stubs here would
 * cause redefinition errors. allocations.h handles the definitions.
 */
/* Step 4b: Block ZSTD_DEPS_COMMON so zstd_deps.h doesn't define __builtin_memcpy
 * macros for ZSTD_memcpy/memset/memmove. */
#define ZSTD_DEPS_COMMON
/* Provide safe BPF implementations of ZSTD_memcpy/memset/memmove. */
static inline void *__bpf_zstd_memcpy(void *dst, const void *src, size_t n)
{{ char *d = (char *)dst; const char *s = (const char *)src; while (n--) *d++ = *s++; return dst; }}
static inline void *__bpf_zstd_memset(void *dst, int c, size_t n)
{{ char *d = (char *)dst; while (n--) *d++ = (char)c; return dst; }}
static inline void *__bpf_zstd_memmove(void *dst, const void *src, size_t n)
{{ char *d = (char *)dst; const char *s = (const char *)src;
   if (d < s) {{ while (n--) *d++ = *s++; }} else {{ d += n; s += n; while (n--) *--d = *--s; }}
   return dst; }}
#define ZSTD_memcpy __bpf_zstd_memcpy
#define ZSTD_memset __bpf_zstd_memset
#define ZSTD_memmove __bpf_zstd_memmove
/* Step 5: Rename cross-TU non-static functions with >5 args.
 * Stubs are provided in EXTRA_PREAMBLE (after the source include) so that
 * ZSTD_DCtx, ZSTD_seqSymbol, U32 etc. are fully defined. */
#define ZSTD_decompressBlock_internal __bpf_ZSTD_decompressBlock_internal
#define ZSTD_buildFSETable __bpf_ZSTD_buildFSETable
