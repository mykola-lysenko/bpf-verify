/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF shim: linux/uaccess.h
 *
 * The real header reaches linux/sched.h and x86 uaccess inline asm.  Model
 * the generic API surface without performing user memory access: user copies
 * report that all bytes remain uncopied and get_user/put_user fail.
 */
#ifndef __LINUX_UACCESS_H__
#define __LINUX_UACCESS_H__

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/ucopysize.h>

#ifndef __user
#define __user
#endif

#ifndef untagged_addr
#define untagged_addr(addr) (addr)
#endif

#ifndef untagged_addr_remote
#define untagged_addr_remote(mm, addr) untagged_addr(addr)
#endif

#define access_ok(addr, size) (1)

#define can_do_masked_user_access() 0
#define masked_user_access_begin(src) ((void *)0)
#define masked_user_read_access_begin(src) ((void *)0)
#define masked_user_write_access_begin(src) ((void *)0)
#define masked_user_rw_access_begin(src) masked_user_access_begin(src)
#define mask_user_address(src) (src)

static inline unsigned long __must_check
raw_copy_from_user(void *to, const void __user *from, unsigned long n)
{
	return n;
}

static inline unsigned long __must_check
raw_copy_to_user(void __user *to, const void *from, unsigned long n)
{
	return n;
}

static inline unsigned long __must_check
__copy_from_user(void *to, const void __user *from, unsigned long n)
{
	return raw_copy_from_user(to, from, n);
}

static inline unsigned long __must_check
__copy_to_user(void __user *to, const void *from, unsigned long n)
{
	return raw_copy_to_user(to, from, n);
}

static inline unsigned long __must_check
__copy_from_user_inatomic(void *to, const void __user *from, unsigned long n)
{
	return raw_copy_from_user(to, from, n);
}

static inline unsigned long __must_check
__copy_to_user_inatomic(void __user *to, const void *from, unsigned long n)
{
	return raw_copy_to_user(to, from, n);
}

static inline unsigned long __must_check
copy_from_user(void *to, const void __user *from, unsigned long n)
{
	if (!check_copy_size(to, n, false))
		return n;
	return __copy_from_user(to, from, n);
}

static inline unsigned long __must_check
copy_to_user(void __user *to, const void *from, unsigned long n)
{
	if (!check_copy_size(from, n, true))
		return n;
	return __copy_to_user(to, from, n);
}

#define get_user(x, ptr) ({ (void)(ptr); (x) = 0; -EFAULT; })
#define __get_user(x, ptr) get_user(x, ptr)
#define put_user(x, ptr) ({ (void)(x); (void)(ptr); -EFAULT; })
#define __put_user(x, ptr) put_user(x, ptr)

#define user_access_begin(ptr, len) access_ok(ptr, len)
#define user_access_end() do { } while (0)
#define user_read_access_begin user_access_begin
#define user_read_access_end user_access_end
#define user_write_access_begin user_access_begin
#define user_write_access_end user_access_end
#define user_rw_access_begin(ptr, len) user_access_begin(ptr, len)
#define user_rw_access_end user_access_end

#define unsafe_op_wrap(op, label) do { if (op) goto label; } while (0)
#define unsafe_get_user(x, ptr, label) unsafe_op_wrap(__get_user(x, ptr), label)
#define unsafe_put_user(x, ptr, label) unsafe_op_wrap(__put_user(x, ptr), label)
#define unsafe_copy_from_user(dst, src, len, label) \
	unsafe_op_wrap(__copy_from_user(dst, src, len), label)
#define unsafe_copy_to_user(dst, src, len, label) \
	unsafe_op_wrap(__copy_to_user(dst, src, len), label)

static inline unsigned long user_access_save(void)
{
	return 0;
}

static inline void user_access_restore(unsigned long flags)
{
}

static inline unsigned long __must_check clear_user(void __user *to,
						    unsigned long n)
{
	return n;
}

static inline void pagefault_disable(void)
{
}

static inline void pagefault_enable(void)
{
}

static inline bool pagefault_disabled(void)
{
	return false;
}

static inline size_t fault_in_readable(const char __user *uaddr, size_t size)
{
	return 0;
}

static inline size_t fault_in_writeable(char __user *uaddr, size_t size)
{
	return 0;
}

static inline size_t fault_in_safe_writeable(const char __user *uaddr,
					     size_t size)
{
	return 0;
}

static inline size_t probe_subpage_writeable(char __user *uaddr, size_t size)
{
	return 0;
}

#endif /* __LINUX_UACCESS_H__ */
