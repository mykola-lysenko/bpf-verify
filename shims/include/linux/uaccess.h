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

#define __bpf_uaccess_noop(...) ((void)0)

#define can_do_masked_user_access() 0
#define masked_user_access_begin(src) ((void *)0)
#define masked_user_read_access_begin masked_user_access_begin
#define masked_user_write_access_begin masked_user_access_begin
#define masked_user_rw_access_begin masked_user_access_begin
#define mask_user_address(src) (src)

static inline unsigned long __must_check
__bpf_uaccess_uncopied(const void *to, const void *from, unsigned long n)
{
	(void)to;
	(void)from;
	return n;
}

#define __bpf_uaccess_copy_fn(name, to_type, from_type)			\
static inline unsigned long __must_check name(to_type to, from_type from, \
					      unsigned long n)		\
{									\
	return __bpf_uaccess_uncopied(to, from, n);			\
}

__bpf_uaccess_copy_fn(raw_copy_from_user, void *, const void __user *)
__bpf_uaccess_copy_fn(raw_copy_to_user, void __user *, const void *)
__bpf_uaccess_copy_fn(__copy_from_user, void *, const void __user *)
__bpf_uaccess_copy_fn(__copy_to_user, void __user *, const void *)
__bpf_uaccess_copy_fn(__copy_from_user_inatomic, void *, const void __user *)
__bpf_uaccess_copy_fn(__copy_to_user_inatomic, void __user *, const void *)

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
#define __get_user get_user
#define put_user(x, ptr) ({ (void)(x); (void)(ptr); -EFAULT; })
#define __put_user put_user

#define user_access_begin(ptr, len) access_ok(ptr, len)
#define user_access_end() __bpf_uaccess_noop()
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

#define user_access_restore(flags) ((void)(flags))

static inline unsigned long __must_check clear_user(void __user *to,
						    unsigned long n)
{
	return __bpf_uaccess_uncopied(to, (const void *)0, n);
}

#define pagefault_disable() __bpf_uaccess_noop()
#define pagefault_enable pagefault_disable

static inline bool pagefault_disabled(void)
{
	return false;
}

#define __bpf_uaccess_fault_fn(name, addr_type)				\
static inline size_t name(addr_type uaddr, size_t size)			\
{									\
	(void)uaddr;							\
	(void)size;							\
	return 0;							\
}

__bpf_uaccess_fault_fn(fault_in_readable, const char __user *)
__bpf_uaccess_fault_fn(fault_in_writeable, char __user *)
__bpf_uaccess_fault_fn(fault_in_safe_writeable, const char __user *)
__bpf_uaccess_fault_fn(probe_subpage_writeable, char __user *)

#endif /* __LINUX_UACCESS_H__ */
