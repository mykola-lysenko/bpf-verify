/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: model lock APIs as single-threaded no-ops. */
#ifndef __LINUX_SPINLOCK_H
#define __LINUX_SPINLOCK_H

#include <linux/preempt.h>
#include <linux/irqflags.h>
#include <linux/bottom_half.h>
#include <linux/spinlock_types.h>
#include <linux/cleanup.h>

#define __bpf_lock_noop(...)		do { (void)(__VA_ARGS__); } while (0)
#define __bpf_lock_irqsave(lock, flags)	do { (void)(lock); (flags) = 0; } while (0)
#define __bpf_lock_try(...)		({ (void)(__VA_ARGS__); 1; })
#define __bpf_lock_try_irqsave(lock, flags)	\
	({ (void)(lock); (flags) = 0; 1; })
#define __bpf_lock_false(...)		({ (void)(__VA_ARGS__); 0; })

#define raw_spin_lock_init(...)		__bpf_lock_noop(__VA_ARGS__)
#define raw_spin_lock			raw_spin_lock_init
#define raw_spin_lock_nested		raw_spin_lock_init
#define raw_spin_lock_nest_lock		raw_spin_lock_init
#define raw_spin_lock_bh		raw_spin_lock_init
#define raw_spin_lock_irq		raw_spin_lock_init
#define raw_spin_lock_irqsave(lock, flags)	__bpf_lock_irqsave(lock, flags)
#define raw_spin_lock_irqsave_nested(lock, flags, subclass)	\
	do { (void)(subclass); __bpf_lock_irqsave(lock, flags); } while (0)
#define raw_spin_unlock		raw_spin_lock_init
#define raw_spin_unlock_bh		raw_spin_lock_init
#define raw_spin_unlock_irq		raw_spin_lock_init
#define raw_spin_unlock_irqrestore	raw_spin_lock_init
#define raw_spin_trylock(...)		__bpf_lock_try(__VA_ARGS__)
#define raw_spin_trylock_bh		raw_spin_trylock
#define raw_spin_trylock_irq		raw_spin_trylock
#define raw_spin_trylock_irqsave(lock, flags)	__bpf_lock_try_irqsave(lock, flags)
#define raw_spin_is_locked(...)		__bpf_lock_false(__VA_ARGS__)
#define raw_spin_is_contended		raw_spin_is_locked
#define assert_raw_spin_locked		raw_spin_lock_init

static inline raw_spinlock_t *spinlock_check(spinlock_t *lock)
{
	return &lock->rlock;
}

#define spin_lock_init(lock)		raw_spin_lock_init(spinlock_check(lock))
#define spin_lock(lock)			raw_spin_lock(spinlock_check(lock))
#define spin_lock_nested(lock, subclass) \
	raw_spin_lock_nested(spinlock_check(lock), subclass)
#define spin_lock_nest_lock(lock, nest_lock) \
	raw_spin_lock_nest_lock(spinlock_check(lock), nest_lock)
#define spin_lock_bh(lock)		raw_spin_lock_bh(spinlock_check(lock))
#define spin_lock_irq(lock)		raw_spin_lock_irq(spinlock_check(lock))
#define spin_lock_irqsave(lock, flags) \
	raw_spin_lock_irqsave(spinlock_check(lock), flags)
#define spin_lock_irqsave_nested(lock, flags, subclass) \
	raw_spin_lock_irqsave_nested(spinlock_check(lock), flags, subclass)
#define spin_unlock(lock)		raw_spin_unlock(spinlock_check(lock))
#define spin_unlock_bh(lock)		raw_spin_unlock_bh(spinlock_check(lock))
#define spin_unlock_irq(lock)		raw_spin_unlock_irq(spinlock_check(lock))
#define spin_unlock_irqrestore(lock, flags) \
	raw_spin_unlock_irqrestore(spinlock_check(lock), flags)
#define spin_trylock(lock)		raw_spin_trylock(spinlock_check(lock))
#define spin_trylock_bh(lock)		raw_spin_trylock_bh(spinlock_check(lock))
#define spin_trylock_irq(lock)		raw_spin_trylock_irq(spinlock_check(lock))
#define spin_trylock_irqsave(lock, flags) \
	raw_spin_trylock_irqsave(spinlock_check(lock), flags)
#define spin_is_locked(lock)		raw_spin_is_locked(spinlock_check(lock))
#define spin_is_contended(lock)		raw_spin_is_contended(spinlock_check(lock))
#define spin_needbreak(lock)		spin_is_contended(lock)
#define assert_spin_locked(lock)	assert_raw_spin_locked(spinlock_check(lock))
#define smp_mb__after_spinlock()		do { } while (0)

#define rwlock_init			raw_spin_lock_init
#define read_lock			raw_spin_lock_init
#define read_lock_bh			raw_spin_lock_init
#define read_lock_irq			raw_spin_lock_init
#define read_lock_irqsave		raw_spin_lock_irqsave
#define read_unlock			raw_spin_lock_init
#define read_unlock_bh			raw_spin_lock_init
#define read_unlock_irq			raw_spin_lock_init
#define read_unlock_irqrestore		raw_spin_lock_init
#define read_trylock			raw_spin_trylock
#define write_lock			raw_spin_lock_init
#define write_lock_nested		raw_spin_lock_init
#define write_lock_bh			raw_spin_lock_init
#define write_lock_irq			raw_spin_lock_init
#define write_lock_irqsave		raw_spin_lock_irqsave
#define write_unlock			raw_spin_lock_init
#define write_unlock_bh			raw_spin_lock_init
#define write_unlock_irq		raw_spin_lock_init
#define write_unlock_irqrestore		raw_spin_lock_init
#define write_trylock			raw_spin_trylock
#define write_trylock_irqsave		raw_spin_trylock_irqsave
#define rwlock_is_contended		raw_spin_is_locked
#define rwlock_needbreak		raw_spin_is_locked

#endif /* __LINUX_SPINLOCK_H */
