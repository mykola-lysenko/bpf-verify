// SPDX-License-Identifier: GPL-2.0-only
/* BPF shim: kernel/bpf/tnum.c
 * #include the real source with all functions forced to always_inline.
 * tnum functions return struct tnum by value (StructRet ABI), which
 * some LLVM versions reject for BPF. Inlining avoids StructRet. */

#pragma clang attribute push(__attribute__((always_inline)), apply_to=function)
#include "kernel/bpf/tnum.c"
#pragma clang attribute pop
