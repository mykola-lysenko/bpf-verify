/* BPF shim: linux/irq_work.h
 *
 * The real irq_work.h pulls in SMP/IPI machinery. Several headers (e.g.
 * srcutree.h) only need `struct irq_work` to be a *complete* type so they can
 * embed it by value. Provide a minimal complete stub -- irq_work is never
 * executed under BPF, so its layout is irrelevant.
 */
#ifndef _LINUX_IRQ_WORK_H
#define _LINUX_IRQ_WORK_H

struct irq_work {
	void *__bpf_irq_work_pad[4];
};

#define IRQ_WORK_INIT(_func) { }
#define DEFINE_IRQ_WORK(name, _func) struct irq_work name = IRQ_WORK_INIT(_func)

static inline void init_irq_work(struct irq_work *work, void (*func)(struct irq_work *)) { (void)work; (void)func; }
static inline bool irq_work_queue(struct irq_work *work) { (void)work; return false; }
static inline void irq_work_sync(struct irq_work *work) { (void)work; }

#endif /* _LINUX_IRQ_WORK_H */
