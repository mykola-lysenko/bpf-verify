/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: linux/rwsem.h
 *
 * Verifier harnesses compile lock-manipulation call paths but do not model
 * sleeping lock state. Keep the rwsem type and API surface as inert helpers.
 */
#ifndef _LINUX_RWSEM_H
#define _LINUX_RWSEM_H

struct rw_semaphore {
	long count;
};

#define __RWSEM_INITIALIZER(name)	{ .count = 0 }
#define DECLARE_RWSEM(name)		struct rw_semaphore name = __RWSEM_INITIALIZER(name)

static inline void init_rwsem(struct rw_semaphore *sem)
{
	sem->count = 0;
}

static inline void down_read(struct rw_semaphore *sem) { (void)sem; }
static inline int down_read_trylock(struct rw_semaphore *sem)
{
	(void)sem;
	return 1;
}
static inline int down_read_killable(struct rw_semaphore *sem)
{
	(void)sem;
	return 0;
}
static inline void up_read(struct rw_semaphore *sem) { (void)sem; }
static inline void up_read_non_owner(struct rw_semaphore *sem) { (void)sem; }

static inline void down_write(struct rw_semaphore *sem) { (void)sem; }
static inline void down_write_nested(struct rw_semaphore *sem, int subclass)
{
	(void)sem;
	(void)subclass;
}
static inline int down_write_killable(struct rw_semaphore *sem)
{
	(void)sem;
	return 0;
}
static inline int down_write_trylock(struct rw_semaphore *sem)
{
	(void)sem;
	return 1;
}
static inline void up_write(struct rw_semaphore *sem) { (void)sem; }
static inline void downgrade_write(struct rw_semaphore *sem) { (void)sem; }

static inline int rwsem_is_locked(struct rw_semaphore *sem)
{
	(void)sem;
	return 0;
}

static inline int rwsem_is_contended(struct rw_semaphore *sem)
{
	(void)sem;
	return 0;
}

#define rwsem_assert_held(sem)		do { (void)(sem); } while (0)
#define rwsem_assert_held_write(sem)	do { (void)(sem); } while (0)

#endif /* _LINUX_RWSEM_H */
