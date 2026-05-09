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

/* Suppress initcall registration. The public initcall macros funnel through
 * these roots; __exitcall emits a pointer directly. */
#undef ____define_initcall
#undef __unique_initcall
#undef ___define_initcall
#undef __define_initcall
#undef __exitcall
#define ____define_initcall(...)
#define __unique_initcall(...)
#define ___define_initcall(...)
#define __define_initcall(...)
#define __exitcall(...)

/* Boot parameter registration also uses init sections. Keep parser functions
 * compileable, but do not emit setup tables. */
#undef __setup_param
#undef early_param_on_off
#define __setup_param(...)
#define early_param_on_off(str_on, str_off, var, config) \
	int var = IS_ENABLED(config)

/* Non-module BPF builds should not retain exit-only function pointers. */
#undef __exit_p
#define __exit_p(x) ((void *)0)

#endif /* _BPF_SHIM_LINUX_INIT_H */
