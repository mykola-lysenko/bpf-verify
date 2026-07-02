/* The shared shims/lz4/linux/lz4.h shim applies internal_linkage to LZ4
 * declarations. Pre-include lz4defs.h only to override LZ4_memcpy before
 * lz4_compress.c includes it. */
/* Pre-include lz4defs.h so its include guard prevents re-inclusion */
#include "{ksrc}/lib/lz4/lz4defs.h"
#undef LZ4_memcpy
#define LZ4_memcpy(dst, src, size) memcpy(dst, src, size)
