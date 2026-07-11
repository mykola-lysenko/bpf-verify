/* BPF shim: linux/shm.h
 *
 * SysV shared memory. Pulled in transitively (via sched.h) by some lib files
 * but never used by lib code -- and the real header uses -ENOSYS in a static
 * inline without including errno.h, breaking the standalone build. Stub it out.
 */
#ifndef _LINUX_SHM_H
#define _LINUX_SHM_H
#include <linux/types.h>
struct shmid_kernel;
struct sysv_shm { struct list_head shm_clist; };
static inline long do_shmat(int a, char __user *b, int c, unsigned long *d, unsigned long e) { return 0; }
static inline void exit_shm(struct task_struct *t) { }
static inline void shm_init_task(struct task_struct *t) { }
#endif /* _LINUX_SHM_H */
