/* BPF shim: asm/bug.h
 * x86 bug.h uses UD2 inline asm and pushsection directives not valid in BPF.
 * Provide BPF-safe no-op implementations.
 */
#ifndef _ASM_X86_BUG_H
#define _ASM_X86_BUG_H

/* Block asm-generic/bug.h from redefining these */
#define _ASM_GENERIC_BUG_H

/* TAINT values needed by asm-generic/bug.h */
#define TAINT_WARN		9

/* Bug flags */
#define BUGFLAG_WARNING		(1 << 0)
#define BUGFLAG_ONCE		(1 << 1)
#define BUGFLAG_DONE		(1 << 2)
#define BUGFLAG_NO_CUT_HERE	(1 << 3)
#define BUGFLAG_TAINT(taint)	((taint) << 8)
#define BUG_GET_TAINT(bug)	((bug)->flags >> 8)

/* Minimal bug_entry struct for linux/bug.h */
struct bug_entry {
	int		bug_addr_disp;
#ifdef CONFIG_DEBUG_BUGVERBOSE
	int		file_disp;
	unsigned short	line;
#endif
	unsigned short	flags;
};

/* BPF-safe BUG/WARN implementations */
#define BUG()			do { } while (0)
#define BUG_ON(cond)		do { if (cond) { } } while (0)
#define WARN_ON(cond)		(!!(cond))
#define WARN_ON_ONCE(cond)	(!!(cond))
#define WARN(cond, fmt...)	(!!(cond))
#define WARN_ONCE(cond, fmt...)	(!!(cond))
#define WARN_TAINT(cond, taint, fmt...)	(!!(cond))
#define WARN_TAINT_ONCE(cond, taint, fmt...)	(!!(cond))

/* __WARN_FLAGS needed by asm-generic/bug.h */
#define __WARN_FLAGS(flags)	do { } while (0)

#endif /* _ASM_X86_BUG_H */
