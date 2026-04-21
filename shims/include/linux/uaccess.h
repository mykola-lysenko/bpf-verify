/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF shim: linux/uaccess.h
 *
 * The real uaccess.h includes linux/sched.h which pulls in the full task
 * scheduler type system — too deep for BPF compilation of lib/ targets.
 *
 * This shim provides minimal stubs for user-space memory access functions.
 * The lib/ targets that use checksum/string functions don't actually call
 * copy_from_user/copy_to_user at verification time; we just need the types
 * and function declarations to compile.
 */
#ifndef __LINUX_UACCESS_H__
#define __LINUX_UACCESS_H__

#include <linux/types.h>
#include <linux/compiler.h>

/* __user annotation — already defined in compiler_types.h, but ensure it's here */
#ifndef __user
#define __user
#endif

/* Minimal access_ok stub */
#define access_ok(addr, size) (1)

/* copy_from_user / copy_to_user stubs */
static inline unsigned long copy_from_user(void *to, const void __user *from, unsigned long n)
{
	return n; /* pretend failure — not called in BPF verification */
}

static inline unsigned long copy_to_user(void __user *to, const void *from, unsigned long n)
{
	return n; /* pretend failure — not called in BPF verification */
}

static inline unsigned long __copy_from_user(void *to, const void __user *from, unsigned long n)
{
	return n;
}

static inline unsigned long __copy_to_user(void __user *to, const void *from, unsigned long n)
{
	return n;
}

/* get_user / put_user stubs */
#define get_user(x, ptr) ({ (x) = 0; -EFAULT; })
#define put_user(x, ptr) (-EFAULT)

/* pagefault_disable/enable stubs */
static inline void pagefault_disable(void) {}
static inline void pagefault_enable(void) {}
static inline bool pagefault_disabled(void) { return false; }

/* uaccess_begin/end stubs */
static inline void uaccess_begin(void) {}
static inline void uaccess_end(void) {}

/* fault_in_readable / fault_in_writeable stubs */
static inline int fault_in_readable(const char __user *uaddr, size_t size) { return 0; }
static inline int fault_in_writeable(char __user *uaddr, size_t size) { return 0; }
static inline int fault_in_safe_writeable(const char __user *uaddr, size_t size) { return 0; }

#endif /* __LINUX_UACCESS_H__ */
