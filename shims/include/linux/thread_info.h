/* BPF shim: linux/thread_info.h
 *
 * The kernel's thread_info.h pulls in stackprotector.h (x86 segment-register
 * asm) and check_copy_size/copy_overflow which reference task_struct internals.
 * This shim provides the essentials for BPF compilation.
 */
#ifndef _LINUX_THREAD_INFO_H
#define _LINUX_THREAD_INFO_H

#include <linux/types.h>
#include <linux/bitops.h>

#define THREAD_ALIGN	THREAD_SIZE

static inline void check_object_size(const void *ptr, unsigned long n,
				     bool to_user) { }

static inline void copy_overflow(int size, unsigned long count) { }

static inline __must_check bool
check_copy_size(const void *addr, size_t bytes, bool is_source)
{
	return true;
}

#endif /* _LINUX_THREAD_INFO_H */
