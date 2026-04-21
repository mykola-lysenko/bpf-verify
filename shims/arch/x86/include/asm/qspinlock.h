/* BPF shim: asm/qspinlock.h
 * x86 qspinlock.h uses GEN_BINARY_RMWcc inline assembly.
 * Provide BPF-safe no-op spinlock stubs.
 */
#ifndef _ASM_X86_QSPINLOCK_H
#define _ASM_X86_QSPINLOCK_H

#include <asm-generic/qspinlock_types.h>

/* BPF doesn't need real locking - provide no-op stubs */
static inline void queued_spin_lock(struct qspinlock *lock) {}
static inline void queued_spin_unlock(struct qspinlock *lock) {}
static inline int queued_spin_trylock(struct qspinlock *lock) { return 1; }
static inline int queued_spin_is_locked(struct qspinlock *lock) { return 0; }
static inline int queued_spin_is_contended(struct qspinlock *lock) { return 0; }
static inline int queued_spin_value_unlocked(struct qspinlock lock) { return 1; }

#define arch_spin_is_locked(l)		queued_spin_is_locked(l)
#define arch_spin_is_contended(l)	queued_spin_is_contended(l)
#define arch_spin_value_unlocked(l)	queued_spin_value_unlocked(l)
#define arch_spin_lock(l)		queued_spin_lock(l)
#define arch_spin_trylock(l)		queued_spin_trylock(l)
#define arch_spin_unlock(l)		queued_spin_unlock(l)

/* queued_fetch_set_pending_acquire - not needed for BPF */
static inline u32 queued_fetch_set_pending_acquire(struct qspinlock *lock)
{
	return 0;
}

#endif /* _ASM_X86_QSPINLOCK_H */
