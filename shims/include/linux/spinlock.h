/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: model lock APIs as single-threaded no-ops. */
#ifndef __LINUX_SPINLOCK_H
#define __LINUX_SPINLOCK_H

#include <linux/preempt.h>
#include <linux/irqflags.h>
#include <linux/bottom_half.h>
#include <linux/spinlock_types.h>
#include <linux/cleanup.h>

#define __bpf_lock_noop(lock)		do { (void)(lock); } while (0)
#define __bpf_lock_noop2(lock, arg)	do { (void)(lock); (void)(arg); } while (0)
#define __bpf_lock_irqsave(lock, flags)	do { (void)(lock); (flags) = 0; } while (0)
#define __bpf_lock_try(lock)		({ (void)(lock); 1; })
#define __bpf_lock_try_irqsave(lock, flags)	\
	({ (void)(lock); (flags) = 0; 1; })

#define raw_spin_lock_init(lock)		__bpf_lock_noop(lock)
#define raw_spin_lock(lock)			__bpf_lock_noop(lock)
#define raw_spin_lock_nested(lock, subclass)	__bpf_lock_noop2(lock, subclass)
#define raw_spin_lock_nest_lock(lock, nest_lock) __bpf_lock_noop2(lock, nest_lock)
#define raw_spin_lock_bh(lock)			__bpf_lock_noop(lock)
#define raw_spin_lock_irq(lock)			__bpf_lock_noop(lock)
#define raw_spin_lock_irqsave(lock, flags)	__bpf_lock_irqsave(lock, flags)
#define raw_spin_lock_irqsave_nested(lock, flags, subclass)	\
	do { (void)(subclass); __bpf_lock_irqsave(lock, flags); } while (0)
#define raw_spin_unlock(lock)			__bpf_lock_noop(lock)
#define raw_spin_unlock_bh(lock)		__bpf_lock_noop(lock)
#define raw_spin_unlock_irq(lock)		__bpf_lock_noop(lock)
#define raw_spin_unlock_irqrestore(lock, flags)	__bpf_lock_noop2(lock, flags)
#define raw_spin_trylock(lock)			__bpf_lock_try(lock)
#define raw_spin_trylock_bh(lock)		__bpf_lock_try(lock)
#define raw_spin_trylock_irq(lock)		__bpf_lock_try(lock)
#define raw_spin_trylock_irqsave(lock, flags)	__bpf_lock_try_irqsave(lock, flags)
#define raw_spin_is_locked(lock)		({ (void)(lock); 0; })
#define raw_spin_is_contended(lock)		({ (void)(lock); 0; })
#define assert_raw_spin_locked(lock)		__bpf_lock_noop(lock)

#define spin_lock_init(lock)			__bpf_lock_noop(lock)
#define spin_lock(lock)				__bpf_lock_noop(lock)
#define spin_lock_nested(lock, subclass)	__bpf_lock_noop2(lock, subclass)
#define spin_lock_nest_lock(lock, nest_lock)	__bpf_lock_noop2(lock, nest_lock)
#define spin_lock_bh(lock)			__bpf_lock_noop(lock)
#define spin_lock_irq(lock)			__bpf_lock_noop(lock)
#define spin_lock_irqsave(lock, flags)		__bpf_lock_irqsave(lock, flags)
#define spin_lock_irqsave_nested(lock, flags, subclass)	\
	do { (void)(subclass); __bpf_lock_irqsave(lock, flags); } while (0)
#define spin_unlock(lock)			__bpf_lock_noop(lock)
#define spin_unlock_bh(lock)			__bpf_lock_noop(lock)
#define spin_unlock_irq(lock)			__bpf_lock_noop(lock)
#define spin_unlock_irqrestore(lock, flags)	__bpf_lock_noop2(lock, flags)
#define spin_trylock(lock)			__bpf_lock_try(lock)
#define spin_trylock_bh(lock)			__bpf_lock_try(lock)
#define spin_trylock_irq(lock)			__bpf_lock_try(lock)
#define spin_trylock_irqsave(lock, flags)	__bpf_lock_try_irqsave(lock, flags)
#define spin_is_locked(lock)			({ (void)(lock); 0; })
#define spin_is_contended(lock)			({ (void)(lock); 0; })
#define spin_needbreak(lock)			({ (void)(lock); 0; })
#define assert_spin_locked(lock)		__bpf_lock_noop(lock)
#define smp_mb__after_spinlock()		do { } while (0)

#define rwlock_init(lock)			__bpf_lock_noop(lock)
#define read_lock(lock)				__bpf_lock_noop(lock)
#define read_lock_bh(lock)			__bpf_lock_noop(lock)
#define read_lock_irq(lock)			__bpf_lock_noop(lock)
#define read_lock_irqsave(lock, flags)		__bpf_lock_irqsave(lock, flags)
#define read_unlock(lock)			__bpf_lock_noop(lock)
#define read_unlock_bh(lock)			__bpf_lock_noop(lock)
#define read_unlock_irq(lock)			__bpf_lock_noop(lock)
#define read_unlock_irqrestore(lock, flags)	__bpf_lock_noop2(lock, flags)
#define read_trylock(lock)			__bpf_lock_try(lock)
#define write_lock(lock)			__bpf_lock_noop(lock)
#define write_lock_nested(lock, subclass)	__bpf_lock_noop2(lock, subclass)
#define write_lock_bh(lock)			__bpf_lock_noop(lock)
#define write_lock_irq(lock)			__bpf_lock_noop(lock)
#define write_lock_irqsave(lock, flags)		__bpf_lock_irqsave(lock, flags)
#define write_unlock(lock)			__bpf_lock_noop(lock)
#define write_unlock_bh(lock)			__bpf_lock_noop(lock)
#define write_unlock_irq(lock)			__bpf_lock_noop(lock)
#define write_unlock_irqrestore(lock, flags)	__bpf_lock_noop2(lock, flags)
#define write_trylock(lock)			__bpf_lock_try(lock)
#define write_trylock_irqsave(lock, flags)	__bpf_lock_try_irqsave(lock, flags)
#define rwlock_is_contended(lock)		({ (void)(lock); 0; })
#define rwlock_needbreak(lock)			({ (void)(lock); 0; })

#endif /* __LINUX_SPINLOCK_H */
