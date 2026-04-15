/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: asm/word-at-a-time.h
 *
 * The real x86 word-at-a-time.h defines load_unaligned_zeropad() using
 * inline assembly with _ASM_EXTABLE_TYPE(EX_TYPE_ZEROPAD) — a fixup table
 * entry that is not valid in BPF context.
 *
 * For BPF verification purposes, we replace load_unaligned_zeropad() with a
 * plain unaligned load. In BPF we are not executing on real hardware, so
 * there is no risk of page-fault on a cross-page access; the verifier will
 * reject any unsafe memory access before execution.
 *
 * All other word-at-a-time primitives (has_zero, find_zero, create_zero_mask,
 * count_masked_bytes, etc.) are pure C and are included from the real header
 * via #include_next after blocking the load_unaligned_zeropad definition.
 */
#ifndef _ASM_WORD_AT_A_TIME_H
#define _ASM_WORD_AT_A_TIME_H

/* Pre-define the include guard so the real header's #ifndef guard is false
 * when reached via #include_next — but we ARE the first include, so we use
 * #include_next to get the real content and then override the asm function.
 *
 * Strategy: rename load_unaligned_zeropad to a private symbol before
 * including the real header, then undefine the rename and provide our own
 * pure-C version.
 */

/* Step 1: Rename the asm function so it compiles to an unused symbol. */
#define load_unaligned_zeropad __bpf_load_unaligned_zeropad_asm_unused

/* Step 2: Include the real header (gets struct word_at_a_time, has_zero, etc.) */
#include_next <asm/word-at-a-time.h>

/* Step 3: Undefine the rename and provide a pure-C replacement. */
#undef load_unaligned_zeropad

static __always_inline unsigned long load_unaligned_zeropad(const void *addr)
{
	/* Plain load — safe in BPF context where the verifier ensures
	 * memory safety before any program is executed. */
	unsigned long val;
	__builtin_memcpy(&val, addr, sizeof(val));
	return val;
}

#endif /* _ASM_WORD_AT_A_TIME_H */
