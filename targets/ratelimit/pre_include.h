
/* Block spinlock.h, sched.h, jiffies.h, lockdep_types.h, rwlock.h,
 * and compiler-context-analysis.h to avoid context_lock_struct redefinition */
#define _LINUX_SPINLOCK_H
#define __LINUX_SPINLOCK_H
#define _LINUX_SPINLOCK_TYPES_H
#define __LINUX_SPINLOCK_TYPES_H
#define _LINUX_SPINLOCK_TYPES_RAW_H
#define __LINUX_SPINLOCK_TYPES_RAW_H
#define _LINUX_LOCKDEP_TYPES_H
#define _LINUX_RWLOCK_TYPES_H
#define _LINUX_RWLOCK_H
#define _LINUX_COMPILER_CONTEXT_ANALYSIS_H
#define _LINUX_SCHED_H
#define _LINUX_JIFFIES_H
/* Minimal stubs */
struct raw_spinlock { unsigned int lock; };
typedef struct raw_spinlock raw_spinlock_t;
typedef struct { raw_spinlock_t rlock; } spinlock_t;
#define spin_lock_irqsave(l, f)      do {} while (0)
#define spin_unlock_irqrestore(l, f) do {} while (0)
#define raw_spin_lock_init(lock)     do {} while (0)
/* Provide jiffies as a static variable (not extern) to avoid BTF extern reference */
static unsigned long jiffies = 0;
#define HZ 1000
#define msecs_to_jiffies(ms) ((ms) * HZ / 1000)
#define time_is_before_jiffies(a) ((long)((a) - jiffies) < 0)
static __always_inline void *__bpf_memset(void *dst, int c, __kernel_size_t n)
{
    unsigned char *d = dst;
    __kernel_size_t i;
    for (i = 0; i < n; i++) d[i] = (unsigned char)c;
    return dst;
}
#define memset(dst, c, n) __bpf_memset((dst), (c), (n))
#define atomic_set(v, i) ((v)->counter = (i))
#define atomic_read(v) ((v)->counter)
#define atomic_inc(v) ((v)->counter += 1)
#define atomic_xchg_relaxed(v, i) ({ int __old = (v)->counter; (v)->counter = (i); __old; })
/* ratelimit.h already defines ratelimit_state_init as static inline.
 * We just need to suppress printk and pr_warn. */
#define printk(fmt, ...) do {} while (0)
#define pr_warn(fmt, ...) do {} while (0)
#define pr_warn_ratelimited(fmt, ...) do {} while (0)
/* Provide raw_spin_trylock_irqsave/unlock stubs BEFORE source include
 * so they have BTF and no unresolved extern reference remains. */
#undef noinline
static __attribute__((noinline)) int bpf_raw_spin_trylock_irqsave(
        raw_spinlock_t *lock, unsigned long *flags) {
    (void)lock; (void)flags; return 1;
}
static __attribute__((noinline)) void bpf_raw_spin_unlock_irqrestore(
        raw_spinlock_t *lock, unsigned long flags) {
    (void)lock; (void)flags;
}
#define raw_spin_trylock_irqsave(lock, flags)     bpf_raw_spin_trylock_irqsave(lock, &(flags))
#define raw_spin_unlock_irqrestore(lock, flags)     bpf_raw_spin_unlock_irqrestore(lock, flags)

/* jiffies: provided as extern in harness template, defined here as 0 for BPF */
