/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: linux/init.h
 * Redefine __init/__exit to strip __section(".init.text") attributes.
 * These sections are not loadable by libbpf and cause -95 EOPNOTSUPP.
 */
#ifndef _BPF_SHIM_LINUX_INIT_H
#define _BPF_SHIM_LINUX_INIT_H

/* Pull in the real init.h first so we get all the other macros */
#include_next <linux/init.h>

/* Strip section placement annotations that produce non-BPF ELF sections. */
#undef __init
#undef __initdata
#undef __initconst
#undef __exit
#undef __exitdata
#undef __exitused
#undef __exit_call
#undef __ref
#undef __refdata
#undef __refconst
#undef __meminit
#undef __meminitdata
#undef __meminitconst
#undef __nosavedata
#define __init
#define __initdata
#define __initconst
#define __exit
#define __exitdata
#define __exitused
#define __exit_call
#define __ref
#define __refdata
#define __refconst
#define __meminit
#define __meminitdata
#define __meminitconst
#define __nosavedata

/* Suppress ALL initcall registration - these create non-BPF ELF sections.
 * __define_initcall is the root macro used by all initcall levels. */
#undef __initcall_id
#undef __initcall_name
#undef __initcall_section
#undef __initcall_stub
#undef __define_initcall_stub
#undef __unique_initcall
#undef ____define_initcall
#undef __define_initcall
#undef ___define_initcall
#undef __initcall
#undef __exitcall
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
#define __initcall_id(fn)
#define __initcall_name(prefix, iid, id)
#define __initcall_section(sec, iid)
#define __initcall_stub(fn, iid, id)
#define __define_initcall_stub(stub, fn)
#define __unique_initcall(fn, id, sec, iid)
#define ____define_initcall(fn, stub, name, sec)
#define __define_initcall(fn, id)
#define ___define_initcall(fn, id, __sec)
#define __initcall(fn)
#define __exitcall(fn)
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

/* Boot parameter registration also uses init sections. Keep parser functions
 * compileable, but do not emit setup tables. */
#undef __setup_param
#undef __setup
#undef early_param
#undef early_param_on_off
#define __setup_param(...)
#define __setup(str, fn)
#define early_param(str, fn)
#define early_param_on_off(str_on, str_off, var, config) \
	int var = IS_ENABLED(config)

/* Non-module BPF builds should not retain exit-only function pointers. */
#undef __exit_p
#define __exit_p(x) ((void *)0)

#endif /* _BPF_SHIM_LINUX_INIT_H */
