/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: linux/ucopysize.h */
#ifndef __LINUX_UCOPYSIZE_H__
#define __LINUX_UCOPYSIZE_H__

#include <linux/compiler.h>
#include <linux/types.h>

static inline void check_object_size(const void *ptr, unsigned long n,
				     bool to_user)
{ }

static inline void copy_overflow(int size, unsigned long count)
{ }

static inline __must_check bool
check_copy_size(const void *addr, size_t bytes, bool is_source)
{
	return true;
}

#endif /* __LINUX_UCOPYSIZE_H__ */
