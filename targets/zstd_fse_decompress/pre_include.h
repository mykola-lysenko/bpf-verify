/* Forward declarations with internal_linkage for all >5-arg non-static
 * functions in fse_decompress.c. Use unsigned int for FSE_DTable (it's a
 * typedef for unsigned int in fse.h). Block fse.h to prevent conflict. */
typedef unsigned int FSE_DTable;
__attribute__((internal_linkage))
size_t FSE_buildDTable_wksp(FSE_DTable *dt, const short *normalizedCounter,
    unsigned maxSymbolValue, unsigned tableLog,
    void *workspace, size_t workspaceSize);
__attribute__((internal_linkage))
size_t FSE_decompress_wksp(void *dst, size_t dstCapacity,
    const void *cSrc, size_t cSrcSize,
    unsigned maxLog, void *workSpace, size_t wkspSize);
__attribute__((internal_linkage))
size_t FSE_decompress_wksp_bmi2(void *dst, size_t dstCapacity,
    const void *cSrc, size_t cSrcSize,
    unsigned maxLog, void *workSpace, size_t wkspSize, int bmi2);
/* Override __GNUC__ to force software fallbacks for __builtin_clz
 * (opcode 192, not supported by BPF backend). bitstream.h uses it. */
#define __GNUC__ 2
/* Block fse.h (both sections) to prevent conflicts. */
#define FSE_H
#define FSE_H_FSE_STATIC_LINKING_ONLY
/* FSE_CTable is defined in the first section of fse.h (which we blocked). */
typedef unsigned int FSE_CTable;
/* fse_decompress.c is a template file that requires these macros.
 * They are normally defined at the bottom of fse.h (which we blocked). */
typedef unsigned char BYTE;
typedef struct { unsigned short newState; unsigned char symbol; unsigned char nbBits; } FSE_decode_t;
#define FSE_FUNCTION_TYPE BYTE
#define FSE_FUNCTION_EXTENSION
#define FSE_DECODE_TYPE FSE_decode_t
/* These constants are defined in the blocked fse.h static-linking-only section.
 * fse_decompress.c uses them directly. */
#define FSE_MAX_MEMORY_USAGE 14
#define FSE_MAX_TABLELOG  (FSE_MAX_MEMORY_USAGE-2)
#define FSE_TABLELOG_ABSOLUTE_MAX 15
#define FSE_MAX_SYMBOL_VALUE 255
/* FSE_DTABLE_SIZE_U32 is defined in the blocked fse.h (public section). */
#define FSE_DTABLE_SIZE_U32(maxTableLog) (1 + (1<<(maxTableLog)))
typedef struct { unsigned short tableLog; unsigned short fastMode; } FSE_DTableHeader;
typedef struct { size_t state; const void *table; } FSE_DState_t;
/* Include bitstream.h to get BIT_DStream_t and the BIT_* inline functions.
 * bitstream.h is normally included by fse.h's static section (which we blocked).
 * With __GNUC__ 2, bitstream.h uses the software fallback for BIT_highbit32
 * instead of __builtin_clz (opcode 192, not supported by BPF). */
#include "{ksrc}/lib/zstd/common/bitstream.h"
/* FSE_initDState/decodeSymbol/decodeSymbolFast are static inline in fse.h's
 * static-linking-only section (which we blocked). Provide stubs so the
 * BPF object has no unresolved extern references. */
static __always_inline void FSE_initDState(FSE_DState_t *s, BIT_DStream_t *b,
    const FSE_DTable *dt)
{ (void)s; (void)b; (void)dt; }
static __always_inline unsigned char FSE_decodeSymbol(FSE_DState_t *s,
    BIT_DStream_t *b)
{ (void)s; (void)b; return 0; }
static __always_inline unsigned char FSE_decodeSymbolFast(FSE_DState_t *s,
    BIT_DStream_t *b)
{ (void)s; (void)b; return 0; }
static __always_inline unsigned FSE_endOfDState(const FSE_DState_t *s)
{ (void)s; return 1; }
