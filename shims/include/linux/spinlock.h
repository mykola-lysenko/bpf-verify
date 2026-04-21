/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: stub out spinlocks - not needed for BPF verification */
#ifndef __LINUX_SPINLOCK_H
#define __LINUX_SPINLOCK_H

#include <linux/preempt.h>
#include <linux/irqflags.h>
#include <linux/bottom_half.h>
#include <linux/spinlock_types.h>
#include <linux/cleanup.h>

/* Spinlock types - spinlock_t and rwlock_t are defined in linux/spinlock_types.h */
#define DEFINE_SPINLOCK(x)      spinlock_t x = { .lock = 0 }
#define DEFINE_RWLOCK(x)        rwlock_t x = { .lock = 0 }
#define __SPIN_LOCK_UNLOCKED(x) { .lock = 0 }
#define SPIN_LOCK_INITIALIZER   { .lock = 0 }

/* Spinlock operations - all no-ops for BPF */
#define spin_lock_init(x)       do {} while (0)
#define spin_lock(x)            do {} while (0)
#define spin_unlock(x)          do {} while (0)
#define spin_lock_bh(x)         do {} while (0)
#define spin_unlock_bh(x)       do {} while (0)
#define spin_lock_irq(x)        do {} while (0)
#define spin_unlock_irq(x)      do {} while (0)
#define spin_lock_irqsave(x,f)  do { (void)(f); } while (0)
#define spin_unlock_irqrestore(x,f) do { (void)(f); } while (0)
#define spin_trylock(x)         1
#define spin_is_locked(x)       0

/* Raw spinlock operations - raw_spinlock_t is defined in linux/spinlock_types_raw.h */

#define raw_spin_lock_init(x)   do {} while (0)
#define raw_spin_lock(x)        do {} while (0)
#define raw_spin_unlock(x)      do {} while (0)
#define raw_spin_lock_irq(x)    do {} while (0)
#define raw_spin_unlock_irq(x)  do {} while (0)
#define raw_spin_lock_irqsave(x,f) do { (void)(f); } while (0)
#define raw_spin_unlock_irqrestore(x,f) do { (void)(f); } while (0)
#define raw_spin_trylock(x)     1
#define raw_spin_is_locked(x)   0
#define DEFINE_RAW_SPINLOCK(x)  raw_spinlock_t x = { .lock = 0 }
#define __RAW_SPIN_LOCK_UNLOCKED(x) { .lock = 0 }

/* RW lock operations */
#define read_lock(x)            do {} while (0)
#define read_unlock(x)          do {} while (0)
#define write_lock(x)           do {} while (0)
#define write_unlock(x)         do {} while (0)
#define read_lock_irq(x)        do {} while (0)
#define read_unlock_irq(x)      do {} while (0)
#define write_lock_irq(x)       do {} while (0)
#define write_unlock_irq(x)     do {} while (0)
#define read_lock_irqsave(x,f)  do { (void)(f); } while (0)
#define read_unlock_irqrestore(x,f) do { (void)(f); } while (0)
#define write_lock_irqsave(x,f) do { (void)(f); } while (0)
#define write_unlock_irqrestore(x,f) do { (void)(f); } while (0)
#define rwlock_init(x)          do {} while (0)

/* Guard/cleanup integration */
DEFINE_LOCK_GUARD_1(spinlock, spinlock_t,
                    spin_lock(_T->lock), spin_unlock(_T->lock))
DEFINE_LOCK_GUARD_1(spinlock_irq, spinlock_t,
                    spin_lock_irq(_T->lock), spin_unlock_irq(_T->lock))
DEFINE_LOCK_GUARD_1(spinlock_irqsave, spinlock_t,
                    spin_lock_irqsave(_T->lock, _T->flags),
                    spin_unlock_irqrestore(_T->lock, _T->flags),
                    unsigned long flags)
DEFINE_LOCK_GUARD_1(raw_spinlock, raw_spinlock_t,
                    raw_spin_lock(_T->lock), raw_spin_unlock(_T->lock))
DEFINE_LOCK_GUARD_1(raw_spinlock_irq, raw_spinlock_t,
                    raw_spin_lock_irq(_T->lock), raw_spin_unlock_irq(_T->lock))
DEFINE_LOCK_GUARD_1(raw_spinlock_irqsave, raw_spinlock_t,
                    raw_spin_lock_irqsave(_T->lock, _T->flags),
                    raw_spin_unlock_irqrestore(_T->lock, _T->flags),
                    unsigned long flags)
DEFINE_LOCK_GUARD_1(read_lock, rwlock_t,
                    read_lock(_T->lock), read_unlock(_T->lock))
DEFINE_LOCK_GUARD_1(write_lock, rwlock_t,
                    write_lock(_T->lock), write_unlock(_T->lock))
DEFINE_LOCK_GUARD_1(read_lock_irqsave, rwlock_t,
                    read_lock_irqsave(_T->lock, _T->flags),
                    read_unlock_irqrestore(_T->lock, _T->flags),
                    unsigned long flags)
DEFINE_LOCK_GUARD_1(write_lock_irqsave, rwlock_t,
                    write_lock_irqsave(_T->lock, _T->flags),
                    write_unlock_irqrestore(_T->lock, _T->flags),
                    unsigned long flags)

#endif /* __LINUX_SPINLOCK_H */
