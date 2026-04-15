/* BPF shim: asm/current.h
 * x86 current.h uses this_cpu_read_stable(%gs:current_task) which is
 * invalid in BPF. Provide a NULL stub since lib/ targets don't use
 * current for their core logic.
 */
#ifndef _ASM_X86_CURRENT_H
#define _ASM_X86_CURRENT_H

#include <linux/compiler.h>

struct task_struct;

/* BPF stub: current is not meaningful in BPF context */
static __always_inline struct task_struct *get_current(void)
{
	return (struct task_struct *)0;
}

#define current get_current()

#endif /* _ASM_X86_CURRENT_H */
