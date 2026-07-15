/* BPF shim: linux/irq_work_types.h (passive shadow of the real header).
 *
 * The real header defines `struct irq_work` (pulling smp_types.h / rcuwait).
 * We shadow it with an opaque, dependency-free stub -- irq_work is never
 * executed under BPF, so its layout is irrelevant. Uses the real include guard
 * (_LINUX_IRQ_WORK_TYPES_H) so whichever of {this shim, the real header} is
 * reached first wins and the other is a no-op: a single definition everywhere.
 *
 * This is a passive shadow (on the include path, pulled only when something
 * #includes irq_work[_types].h), NOT force-included -- so targets that define
 * their own struct irq_work and never pull this header are unaffected.
 */
#ifndef _LINUX_IRQ_WORK_TYPES_H
#define _LINUX_IRQ_WORK_TYPES_H

struct irq_work {
	void *__bpf_irq_work_pad[4];
};

#endif /* _LINUX_IRQ_WORK_TYPES_H */
