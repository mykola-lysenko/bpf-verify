// SPDX-License-Identifier: GPL-2.0-only
/* BPF shim: kernel/bpf/tnum.c
 * The real source is clean — no >5-arg functions, no inline asm,
 * no signed division. Modern LLVM supports struct return values
 * in BPF, so the previous static __always_inline workaround is
 * no longer needed. Just #include the real source. */

#include "kernel/bpf/tnum.c"
