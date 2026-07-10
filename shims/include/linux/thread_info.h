/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: linux/thread_info.h
 *
 * The real header pulls in asm/thread_info.h, which reaches x86 percpu and
 * CPU-feature headers with inline asm.  Keep only the common constants needed
 * by the BPF verification harnesses.
 */
#ifndef _LINUX_THREAD_INFO_H
#define _LINUX_THREAD_INFO_H

#include <linux/types.h>
#include <linux/bitops.h>

enum {
	BAD_STACK = -1,
	NOT_STACK = 0,
	GOOD_FRAME,
	GOOD_STACK,
};

struct thread_info {
	unsigned long		flags;
	unsigned long		syscall_work;
	u32			status;
#ifdef CONFIG_SMP
	u32			cpu;
#endif
};

#define INIT_THREAD_INFO(tsk)	{ .flags = 0 }

#ifndef current_thread_info
#define current_thread_info()	((struct thread_info *)0)
#endif

#ifndef TIF_SIGPENDING
#define TIF_SIGPENDING		1
#endif
#ifndef _TIF_SIGPENDING
#define _TIF_SIGPENDING	BIT(TIF_SIGPENDING)
#endif

#ifndef TIF_NOTIFY_SIGNAL
#define TIF_NOTIFY_SIGNAL	2
#endif
#ifndef _TIF_NOTIFY_SIGNAL
#define _TIF_NOTIFY_SIGNAL	BIT(TIF_NOTIFY_SIGNAL)
#endif

#ifndef TIF_NEED_RESCHED
#define TIF_NEED_RESCHED	4
#endif
#ifndef _TIF_NEED_RESCHED
#define _TIF_NEED_RESCHED	BIT(TIF_NEED_RESCHED)
#endif

#ifndef _TIF_NOTIFY_RESUME
#define _TIF_NOTIFY_RESUME	BIT(TIF_NOTIFY_RESUME)
#endif

#ifndef TIF_NEED_RESCHED_LAZY
#define TIF_NEED_RESCHED_LAZY	TIF_NEED_RESCHED
#endif
#ifndef _TIF_NEED_RESCHED_LAZY
#define _TIF_NEED_RESCHED_LAZY	_TIF_NEED_RESCHED
#endif

static inline void set_ti_thread_flag(struct thread_info *ti, int flag)
{
	set_bit(flag, (unsigned long *)&ti->flags);
}

static inline void clear_ti_thread_flag(struct thread_info *ti, int flag)
{
	clear_bit(flag, (unsigned long *)&ti->flags);
}

static inline int test_and_set_ti_thread_flag(struct thread_info *ti, int flag)
{
	return test_and_set_bit(flag, (unsigned long *)&ti->flags);
}

static inline int test_and_clear_ti_thread_flag(struct thread_info *ti, int flag)
{
	return test_and_clear_bit(flag, (unsigned long *)&ti->flags);
}

static inline int test_ti_thread_flag(struct thread_info *ti, int flag)
{
	return test_bit(flag, (unsigned long *)&ti->flags);
}

#define set_thread_flag(flag) \
	set_ti_thread_flag(current_thread_info(), flag)
#define clear_thread_flag(flag) \
	clear_ti_thread_flag(current_thread_info(), flag)
#define test_thread_flag(flag) \
	test_ti_thread_flag(current_thread_info(), flag)
#define test_and_clear_thread_flag(flag) \
	test_and_clear_ti_thread_flag(current_thread_info(), flag)

#define THREAD_ALIGN	THREAD_SIZE

#endif /* _LINUX_THREAD_INFO_H */
