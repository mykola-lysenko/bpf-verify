/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: asm/word-at-a-time.h
 *
 * The real x86 word-at-a-time.h defines load_unaligned_zeropad() using
 * inline assembly with _ASM_EXTABLE_TYPE(EX_TYPE_ZEROPAD) — a fixup table
 * entry that is not valid in BPF context.
 *
 * For BPF verification purposes, we replace load_unaligned_zeropad() with a
 * plain unaligned load.
 *
 * IMPORTANT: We use a DIFFERENT guard name (__BPF_WORD_AT_A_TIME_SHIM_H)
 * instead of the real header's guard (_ASM_WORD_AT_A_TIME_H). This ensures
 * that when we call #include_next, the real header's #ifndef _ASM_WORD_AT_A_TIME_H
 * check is NOT pre-satisfied, so the real header's body (struct word_at_a_time,
 * WORD_AT_A_TIME_CONSTANTS, has_zero, etc.) IS processed.
 */
#ifndef __BPF_WORD_AT_A_TIME_SHIM_H
#define __BPF_WORD_AT_A_TIME_SHIM_H

/* Step 1: Rename the asm function so it compiles to an unused symbol. */
#define load_unaligned_zeropad __bpf_load_unaligned_zeropad_asm_unused

/* Step 2: Include the real header — provides struct word_at_a_time,
 * WORD_AT_A_TIME_CONSTANTS, has_zero, find_zero, etc. The real header's
 * own include guard (_ASM_WORD_AT_A_TIME_H) prevents double-inclusion. */
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

#endif /* __BPF_WORD_AT_A_TIME_SHIM_H */
