/* The shims/lz4_decompress/linux/lz4.h shim (target-specific override) applies internal_linkage to all
 * LZ4 functions via a targeted pragma. We just need to pre-include lz4defs.h
 * here to override LZ4_memmove/LZ4_memcpy before lz4_decompress.c includes it.
 * The shim is automatically used when lz4_decompress.c includes <linux/lz4.h>
 * because -I{SHIM}/lz4_decompress is prepended to the include path. */
/* Pre-include lz4defs.h so its include guard (__LZ4DEFS_H__) prevents
 * re-inclusion by lz4_decompress.c. This lets us override LZ4_memmove and
 * LZ4_memcpy AFTER lz4defs.h has defined them as __builtin_memmove/__builtin_memcpy.
 * The BPF backend rejects __builtin_memmove/__builtin_memcpy for variable-size
 * copies; we redirect to the kernel's non-builtin memmove/memcpy instead. */
#include "{ksrc}/lib/lz4/lz4defs.h"
#undef LZ4_memmove
#undef LZ4_memcpy
#define LZ4_memmove(dst, src, size) memmove(dst, src, size)
#define LZ4_memcpy(dst, src, size) memcpy(dst, src, size)
