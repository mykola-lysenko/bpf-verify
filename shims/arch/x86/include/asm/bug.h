/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: asm/bug.h
 * x86 bug.h uses UD2 inline asm and pushsection directives not valid in BPF.
 * Provide BPF-safe no-op implementations.
 */
#ifndef _ASM_X86_BUG_H
#define _ASM_X86_BUG_H

#include <linux/compiler.h>

/* Block asm-generic/bug.h from redefining these */
#define _ASM_GENERIC_BUG_H
#define HAVE_ARCH_BUG
#define HAVE_ARCH_BUG_ON
#define HAVE_ARCH_WARN_ON

/* TAINT values needed by asm-generic/bug.h */
#define TAINT_WARN		9

/* Bug flags */
#define BUGFLAG_WARNING		(1 << 0)
#define BUGFLAG_ONCE		(1 << 1)
#define BUGFLAG_DONE		(1 << 2)
#define BUGFLAG_NO_CUT_HERE	(1 << 3)
#define BUGFLAG_ARGS		(1 << 4)
#define BUGFLAG_TAINT(taint)	((taint) << 8)
#define BUG_GET_TAINT(bug)	((bug)->flags >> 8)

#define CUT_HERE		"------------[ cut here ]------------\n"

/* Minimal bug_entry struct for linux/bug.h */
struct bug_entry {
	int		bug_addr_disp;
#ifdef CONFIG_DEBUG_BUGVERBOSE
	int		file_disp;
	unsigned short	line;
#endif
	unsigned short	flags;
};

struct pt_regs;
struct warn_args;

/* Generated harnesses may predefine these; make the shim authoritative. */
#undef BUG
#undef BUG_ON
#undef WARN_ON
#undef WARN_ON_ONCE
#undef WARN_ON_SMP
#undef WARN
#undef WARN_ONCE
#undef WARN_TAINT
#undef WARN_TAINT_ONCE
#undef __WARN
#undef __WARN_FLAGS
#undef __WARN_printf
#undef WARN_CONDITION_STR

#ifndef unlikely
#define unlikely(x)		(x)
#endif

#define __bpf_bug_noop()	do { } while (0)

#define __bpf_warn_flags(cond_str, flags)		\
do {							\
	(void)(flags);					\
} while (0)

#define __bpf_warn_printf(taint, arg...)		\
do {							\
	(void)(taint);					\
} while (0)

#define __bpf_warn_on_flags(condition, flags)				\
({									\
	int __ret_warn_on = !!(condition);				\
	if (unlikely(__ret_warn_on))					\
		__WARN_FLAGS(#condition, flags);			\
	unlikely(__ret_warn_on);					\
})

#define __bpf_warn(condition, taint, format...)				\
({									\
	int __ret_warn_on = !!(condition);				\
	if (unlikely(__ret_warn_on))					\
		__WARN_printf(taint, ##format);				\
	unlikely(__ret_warn_on);					\
})

/* BPF-safe BUG/WARN implementations */
#define BUG()			__bpf_bug_noop()
#define BUG_ON(cond)		do { if (unlikely(cond)) BUG(); } while (0)
#define WARN_ON(cond)		__bpf_warn_on_flags(cond, BUGFLAG_TAINT(TAINT_WARN))
#define WARN_ON_ONCE(cond)						\
	__bpf_warn_on_flags(cond, BUGFLAG_ONCE | BUGFLAG_TAINT(TAINT_WARN))
#ifdef CONFIG_SMP
#define WARN_ON_SMP(cond)	WARN_ON(cond)
#else
#define WARN_ON_SMP(cond)	({ 0; })
#endif
#define WARN(cond, fmt...)	__bpf_warn(cond, TAINT_WARN, ##fmt)
#define WARN_ONCE(cond, fmt...)	__bpf_warn(cond, TAINT_WARN, ##fmt)
#define WARN_TAINT(cond, taint, fmt...)	__bpf_warn(cond, taint, ##fmt)
#define WARN_TAINT_ONCE(cond, taint, fmt...)	__bpf_warn(cond, taint, ##fmt)

#define __WARN()		__WARN_FLAGS("", BUGFLAG_TAINT(TAINT_WARN))
#define __WARN_FLAGS(cond_str, flags)	__bpf_warn_flags(cond_str, flags)
#define __WARN_printf(taint, arg...)	__bpf_warn_printf(taint, ##arg)
#ifdef CONFIG_DEBUG_BUGVERBOSE_DETAILED
#define WARN_CONDITION_STR(cond_str)	"[" cond_str "] "
#else
#define WARN_CONDITION_STR(cond_str)
#endif

#endif /* _ASM_X86_BUG_H */
