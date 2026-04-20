/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: stub out IRQ flag operations */
#ifndef _LINUX_IRQFLAGS_H
#define _LINUX_IRQFLAGS_H

#define local_irq_enable()      do {} while (0)
#define local_irq_disable()     do {} while (0)
#define local_irq_save(flags)   do { (void)(flags); } while (0)
#define local_irq_restore(flags) do { (void)(flags); } while (0)
#define irqs_disabled()         0
#define irqs_disabled_flags(f)  0
#define safe_halt()             do {} while (0)
#define raw_local_irq_enable()  do {} while (0)
#define raw_local_irq_disable() do {} while (0)
#define raw_local_irq_save(f)   do { (void)(f); } while (0)
#define raw_local_irq_restore(f) do { (void)(f); } while (0)
#define raw_local_save_flags(f) do { (void)(f); } while (0)
#define raw_irqs_disabled()     0
#define raw_irqs_disabled_flags(f) 0

typedef unsigned long flags_t;

#endif /* _LINUX_IRQFLAGS_H */
