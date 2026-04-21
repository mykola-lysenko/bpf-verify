/* BPF shim: asm/preempt.h
 * x86 preempt.h uses per-CPU raw_cpu_read/write inline asm not valid in BPF.
 * Provide BPF-safe stubs - preemption is not meaningful in BPF context.
 */
#ifndef __ASM_PREEMPT_H
#define __ASM_PREEMPT_H

#include <linux/types.h>

/* Preempt count stubs - BPF programs are non-preemptible */
#define PREEMPT_NEED_RESCHED	0x80000000
#define PREEMPT_ENABLED		(0 + PREEMPT_NEED_RESCHED)
#define PREEMPT_DISABLED	(1 + PREEMPT_NEED_RESCHED)

static __always_inline int preempt_count(void) { return 0; }
static __always_inline void preempt_count_set(int pc) {}
static __always_inline void __preempt_count_add(int val) {}
static __always_inline void __preempt_count_sub(int val) {}
static __always_inline bool __preempt_count_dec_and_test(void) { return false; }
static __always_inline bool should_resched(int preempt_offset) { return false; }

#define init_task_preempt_count(p)	do { } while (0)
#define init_idle_preempt_count(p, cpu)	do { } while (0)

static __always_inline void set_preempt_need_resched(void) {}
static __always_inline void clear_preempt_need_resched(void) {}
static __always_inline bool test_preempt_need_resched(void) { return false; }

#endif /* __ASM_PREEMPT_H */
