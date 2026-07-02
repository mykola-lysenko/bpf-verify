#include <linux/errno.h>
#undef __percpu
#define __percpu
#define __LINUX_PREEMPT_H
#define _LINUX_TRACE_IRQFLAGS_H
#define __LINUX_PERCPU_H
#define _ASM_X86_RQSPINLOCK_H
#undef READ_ONCE
#undef WRITE_ONCE
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) do { (x) = (v); } while (0)
#define num_possible_cpus() 1U
#define raw_smp_processor_id() 0
#define cpu_possible_mask ((const unsigned long *)0)
#define for_each_possible_cpu(cpu) for ((cpu) = 0; (cpu) < 1; (cpu)++)
#define for_each_cpu_wrap(cpu, mask, start) for ((cpu) = 0; (cpu) < 1; (cpu)++)
#define per_cpu_ptr(ptr, cpu) (ptr)
#define this_cpu_ptr(ptr) (ptr)
typedef struct { u32 locked; } rqspinlock_t;
static inline void raw_res_spin_lock_init(rqspinlock_t *lock)
{ lock->locked = 0; }
static inline int raw_res_spin_lock(rqspinlock_t *lock)
{ (void)lock; return 0; }
static inline void raw_res_spin_unlock(rqspinlock_t *lock)
{ (void)lock; }
static void *__bpf_percpu_alloc(size_t size);
static void __bpf_percpu_free(void *ptr);
#define alloc_percpu(type) ((type *)__bpf_percpu_alloc(sizeof(type)))
#define free_percpu(ptr) __bpf_percpu_free(ptr)
