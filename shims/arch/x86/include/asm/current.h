/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: asm/current.h
 *
 * The real x86 current.h reads the current task pointer through percpu inline
 * asm, which cannot be compiled for the BPF target. Most verifier harnesses
 * only need the symbol to exist while compile-time-dead code is discarded.
 */
#ifndef _ASM_X86_CURRENT_H
#define _ASM_X86_CURRENT_H

#ifndef __ASSEMBLER__
struct task_struct;

static inline struct task_struct *get_current(void)
{
	return (struct task_struct *)0;
}

#ifndef current
#define current get_current()
#endif

#endif /* __ASSEMBLER__ */
#endif /* _ASM_X86_CURRENT_H */
