// SPDX-License-Identifier: GPL-2.0-only
/* BPF shim: kernel/bpf/tnum.c
 * #include the real source with internal_linkage + always_inline.
 * tnum functions return struct tnum by value (StructRet ABI), which
 * the BPF backend rejects for non-static functions. internal_linkage
 * makes them static, always_inline forces inlining at call sites. */

#pragma clang attribute push(\
    __attribute__((always_inline, internal_linkage)), apply_to=function)
#include "kernel/bpf/tnum.c"
#pragma clang attribute pop
