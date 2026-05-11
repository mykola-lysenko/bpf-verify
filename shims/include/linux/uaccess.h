/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF shim: linux/uaccess.h
 *
 * The real header reaches linux/sched.h and x86 uaccess inline asm.  Model
 * the generic API surface without performing user memory access: user copies
 * report that all bytes remain uncopied and get_user/put_user fail.
 *
 * Targets that explicitly define BPF_VERIFY_UACCESS_COPY before including
 * this header get a bounded stack-backed copy model for harness coverage.
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

#ifdef BPF_VERIFY_UACCESS_COPY
#ifndef BPF_VERIFY_UACCESS_COPY_MAX
#define BPF_VERIFY_UACCESS_COPY_MAX 16UL
#endif

#ifdef BPF_VERIFY_UACCESS_NOINLINE
#define __bpf_uaccess_model_fn __attribute__((__noinline__))
#else
#define __bpf_uaccess_model_fn inline
#endif

#define __bpf_uaccess_model(name, args, init, assign)			\
static __bpf_uaccess_model_fn unsigned long __must_check name args	\
{									\
	unsigned char *dst = to;					\
	init								\
	unsigned long i;						\
	if (n > BPF_VERIFY_UACCESS_COPY_MAX)				\
		return n;						\
	for (i = 0; i < BPF_VERIFY_UACCESS_COPY_MAX; i++) {		\
		if (i >= n)						\
			break;						\
		assign;							\
	}								\
	return 0;							\
}

__bpf_uaccess_model(__bpf_uaccess_copy_bytes,
		    (void *to, const void *from, unsigned long n),
		    const unsigned char *src = from;,
		    dst[i] = src[i])
__bpf_uaccess_model(__bpf_uaccess_clear_bytes, (void *to, unsigned long n),,
		    dst[i] = 0)
#undef __bpf_uaccess_model
#undef __bpf_uaccess_model_fn
#endif

static inline unsigned long __must_check
__bpf_uaccess_uncopied(const void *to, const void *from, unsigned long n)
{
#ifdef BPF_VERIFY_UACCESS_COPY
	return __bpf_uaccess_copy_bytes((void *)to, from, n);
#else
	(void)to;
	(void)from;
	return n;
#endif
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

#define __bpf_uaccess_checked_copy_fn(name, helper, to_type, from_type, checked, write) \
static inline unsigned long __must_check name(to_type to, from_type from, unsigned long n) \
{									\
	if (!check_copy_size(checked, n, write))				\
		return n;						\
	return helper(to, from, n);					\
}

__bpf_uaccess_checked_copy_fn(copy_from_user, __copy_from_user, void *, const void __user *, to, false)
__bpf_uaccess_checked_copy_fn(copy_to_user, __copy_to_user, void __user *, const void *, from, true)
#undef __bpf_uaccess_checked_copy_fn

#ifdef BPF_VERIFY_UACCESS_COPY
#define get_user(x, ptr) ({ typeof(*(ptr)) *__bpf_ptr = (typeof(*(ptr)) *)(ptr); (x) = *__bpf_ptr; 0; })
#define put_user(x, ptr) ({ typeof(*(ptr)) *__bpf_ptr = (typeof(*(ptr)) *)(ptr); *__bpf_ptr = (x); 0; })
#else
#define get_user(x, ptr) ({ (void)(ptr); (x) = 0; -EFAULT; })
#define put_user(x, ptr) ({ (void)(x); (void)(ptr); -EFAULT; })
#endif
#define __get_user get_user
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

#define user_access_save() 0UL
#define user_access_restore(flags) ((void)(flags))

static inline unsigned long __must_check clear_user(void __user *to,
						    unsigned long n)
{
#ifdef BPF_VERIFY_UACCESS_COPY
	return __bpf_uaccess_clear_bytes((void *)to, n);
#else
	return __bpf_uaccess_uncopied(to, (const void *)0, n);
#endif
}

#define pagefault_disable() __bpf_uaccess_noop()
#define pagefault_enable pagefault_disable
#define pagefault_disabled() false

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
