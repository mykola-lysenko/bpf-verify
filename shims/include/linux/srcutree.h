/* BPF shim: linux/srcutree.h -- targeted override.
 *
 * The real srcutree.h embeds `struct irq_work` by value (in struct srcu_usage)
 * but never includes its header, so the type is incomplete in our standalone
 * build. Pull the complete type from our irq_work shim first, then defer to the
 * real header via include_next.
 *
 * This is scoped to translation units that actually include srcutree.h (i.e.
 * pull the srcu/RCU chain), so -- unlike a global force-include -- it does not
 * clash with targets (task_iter, ringbuf_*) that define their own struct
 * irq_work and never touch srcu.
 */
#include <linux/irq_work.h>
#include_next <linux/srcutree.h>
