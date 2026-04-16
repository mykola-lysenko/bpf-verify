/* BPF shim: linux/lz4.h for lz4_compress module
 * Same strategy as lz4_decompress shim:
 * Pre-include headers that lz4.h includes (types.h, string.h) so those
 * functions are already declared. Then apply internal_linkage pragma
 * with apply_to=function and include the real lz4.h. Only the NEW LZ4
 * function declarations get internal_linkage. */
#ifndef __BPF_LZ4_COMPRESS_SHIM_H__
#define __BPF_LZ4_COMPRESS_SHIM_H__
/* Step 1: Pre-include headers that lz4.h includes */
#include <linux/types.h>
#include <linux/string.h>
/* Step 2: Apply internal_linkage to all NEW function declarations (only LZ4 funcs) */
#pragma clang attribute push(__attribute__((internal_linkage)), apply_to=function)
/* Step 3: Include the real lz4.h - its includes are no-ops, only LZ4 decls are new */
#include_next <linux/lz4.h>
#pragma clang attribute pop
#endif /* __BPF_LZ4_COMPRESS_SHIM_H__ */
