/* BPF shim: lzo-shim.h
 * Pre-include LZO headers before EXTRA_PRE_INCLUDE defines '#define static'
 * (which would break the static function declarations in lzodefs.h and lzo.h).
 * This file is listed in EXTRA_INCLUDES so it is processed before the source
 * file include and before the EXTRA_PRE_INCLUDE macros take effect.
 */
#ifndef _BPF_LZO_SHIM_H
#define _BPF_LZO_SHIM_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unaligned.h>
#include <linux/lzo.h>

/* Include lzodefs.h from the kernel source tree.
 * The -I{KSRC} flag in the pipeline's include path resolves this. */
#include "lib/lzo/lzodefs.h"

#endif /* _BPF_LZO_SHIM_H */
