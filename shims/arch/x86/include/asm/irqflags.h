/* BPF shim: asm/irqflags.h
 * x86 irqflags.h uses PUSHF/POPF/STI/CLI inline asm not valid in BPF.
 * Provide stubs - IRQ flag manipulation is not needed for lib/ targets.
 */
#ifndef _X86_IRQFLAGS_H_
#define _X86_IRQFLAGS_H_

#include <linux/types.h>

#define __cpuidle

/* IRQ flag stubs */
static inline unsigned long native_save_fl(void) { return 0; }
static inline void native_restore_fl(unsigned long flags) {}
static inline void native_irq_disable(void) {}
static inline void native_irq_enable(void) {}
static inline void native_halt(void) {}
static inline void native_wbinvd(void) {}

/* arch_local_* wrappers */
static inline unsigned long arch_local_save_flags(void) { return 0; }
static inline void arch_local_irq_disable(void) {}
static inline void arch_local_irq_enable(void) {}
static inline void arch_local_irq_restore(unsigned long flags) {}
static inline int arch_irqs_disabled_flags(unsigned long flags) { return 0; }
static inline int arch_irqs_disabled(void) { return 0; }

#define arch_local_irq_save() (0UL)

#endif /* _X86_IRQFLAGS_H_ */
