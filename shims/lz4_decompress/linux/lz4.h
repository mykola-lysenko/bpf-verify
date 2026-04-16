/* BPF shim: linux/lz4.h
 * Strategy: pre-include linux/types.h and linux/string.h (which lz4.h includes)
 * so those functions are already declared. Then apply internal_linkage pragma
 * with apply_to=function and include the real lz4.h. Since types.h and string.h
 * are already included (include guards prevent re-inclusion), only the NEW LZ4
 * function declarations in lz4.h will get internal_linkage.
 * This avoids the "internal_linkage doesn't appear on first declaration" error. */
#ifndef __BPF_LZ4_SHIM_H__
#define __BPF_LZ4_SHIM_H__
/* Step 1: Pre-include headers that lz4.h includes, so they're already declared */
#include <linux/types.h>
#include <linux/string.h>
/* Step 2: Apply internal_linkage to all NEW function declarations (only LZ4 functions,
 * since types.h and string.h functions are already declared above) */
#pragma clang attribute push(__attribute__((internal_linkage)), apply_to=function)
/* Step 3: Include the real lz4.h - its includes are no-ops, only LZ4 decls are new */
#include_next <linux/lz4.h>
#pragma clang attribute pop
#endif /* __BPF_LZ4_SHIM_H__ */
