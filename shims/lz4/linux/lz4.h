/* BPF shim: linux/lz4.h (shared by lz4_compress and lz4_decompress)
 * Pre-include headers that lz4.h includes so their declarations are already
 * visible. Then apply internal_linkage to all NEW function declarations
 * (only LZ4 functions) via a targeted pragma before including the real lz4.h. */
#ifndef __BPF_LZ4_SHIM_H__
#define __BPF_LZ4_SHIM_H__
#include <linux/types.h>
#include <linux/string.h>
#pragma clang attribute push(__attribute__((internal_linkage)), apply_to=function)
#include_next <linux/lz4.h>
#pragma clang attribute pop
#endif /* __BPF_LZ4_SHIM_H__ */
