/* BPF shim: linux/irq_work.h
 *
 * The real irq_work.h pulls in SMP/IPI machinery. Several headers (e.g.
 * srcutree.h) only need `struct irq_work` to be a *complete* type so they can
 * embed it by value. struct irq_work lives in irq_work_types.h (matching the
 * real kernel header layout), giving it a single definition site shared with
 * anything that pulls the types header directly.
 */
#ifndef _LINUX_IRQ_WORK_H
#define _LINUX_IRQ_WORK_H

#include <linux/irq_work_types.h>

#define IRQ_WORK_INIT(_func) { }
#define DEFINE_IRQ_WORK(name, _func) struct irq_work name = IRQ_WORK_INIT(_func)

static inline void init_irq_work(struct irq_work *work, void (*func)(struct irq_work *)) { (void)work; (void)func; }
static inline _Bool irq_work_queue(struct irq_work *work) { (void)work; return 0; }
static inline void irq_work_sync(struct irq_work *work) { (void)work; }

#endif /* _LINUX_IRQ_WORK_H */
