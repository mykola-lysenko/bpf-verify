/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: linux/init.h
 * Redefine __init/__exit to strip __section(".init.text") attributes.
 * These sections are not loadable by libbpf and cause -95 EOPNOTSUPP.
 */
#ifndef _BPF_SHIM_LINUX_INIT_H
#define _BPF_SHIM_LINUX_INIT_H

/* Pull in the real init.h first so we get all the other macros */
#include_next <linux/init.h>

/* Override the section-placing macros to be no-ops for BPF */
#undef __init
#undef __exit
#undef __initdata
#undef __initconst
#undef __exitdata
#undef __exitused
#undef __exit_call
#define __init
#define __exit
#define __initdata
#define __initconst
#define __exitdata
#define __exitused
#define __exit_call

/* Suppress ALL initcall registration - these create non-BPF ELF sections.
 * __define_initcall is the root macro used by all initcall levels. */
#undef __define_initcall
#undef ___define_initcall
#undef ____define_initcall
#undef __initcall
#undef device_initcall
#undef subsys_initcall
#undef subsys_initcall_sync
#undef fs_initcall
#undef fs_initcall_sync
#undef rootfs_initcall
#undef device_initcall_sync
#undef late_initcall
#undef late_initcall_sync
#undef core_initcall
#undef core_initcall_sync
#undef postcore_initcall
#undef postcore_initcall_sync
#undef arch_initcall
#undef arch_initcall_sync
#undef pure_initcall
#undef early_initcall
#undef console_initcall
#define __define_initcall(fn, id)
#define ___define_initcall(fn, id, __sec)
#define __initcall(fn)
#define device_initcall(fn)
#define subsys_initcall(fn)
#define subsys_initcall_sync(fn)
#define fs_initcall(fn)
#define fs_initcall_sync(fn)
#define rootfs_initcall(fn)
#define device_initcall_sync(fn)
#define late_initcall(fn)
#define late_initcall_sync(fn)
#define core_initcall(fn)
#define core_initcall_sync(fn)
#define postcore_initcall(fn)
#define postcore_initcall_sync(fn)
#define arch_initcall(fn)
#define arch_initcall_sync(fn)
#define pure_initcall(fn)
#define early_initcall(fn)
#define console_initcall(fn)

#endif /* _BPF_SHIM_LINUX_INIT_H */
