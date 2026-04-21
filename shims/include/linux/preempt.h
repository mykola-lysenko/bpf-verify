/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: stub out preemption - not needed for BPF verification */
#ifndef _LINUX_PREEMPT_H
#define _LINUX_PREEMPT_H

#include <asm/preempt.h>

/* Stub out preemption schedule functions */
static inline void __preempt_schedule(void) {}
static inline void __preempt_schedule_notrace(void) {}

/* preempt_count accessors */
#define preempt_count()         0
#define preempt_count_add(val)  do {} while (0)
#define preempt_count_sub(val)  do {} while (0)

#define preemptible()           0
#define preempt_disable()       do {} while (0)
#define preempt_enable()        do {} while (0)
#define preempt_disable_notrace() do {} while (0)
#define preempt_enable_notrace()  do {} while (0)
#define preempt_enable_no_resched() do {} while (0)

#define in_task()               1
#define in_interrupt()          0
#define in_softirq()            0
#define in_irq()                0
#define in_nmi()                0
#define in_serving_softirq()    0
#define in_hardirq()            0
#define in_atomic()             0

#define might_sleep()           do {} while (0)
#define might_sleep_if(c)       do {} while (0)
#define cant_sleep()            do {} while (0)
#define cant_migrate()          do {} while (0)
#define non_block_start()       do {} while (0)
#define non_block_end()         do {} while (0)

#endif /* _LINUX_PREEMPT_H */
