/* BPF shim: asm/paravirt.h
 * x86 paravirt.h uses inline asm with x86-specific register constraints
 * (e.g., "=D" for %rdi) that are not valid in BPF context.
 *
 * This shim replaces the real paravirt.h entirely. The real header is
 * only needed for paravirtualization hooks (Xen, KVM guest mode) which
 * are not relevant for BPF verification of lib/ kernel code.
 *
 * We provide minimal stubs for the symbols that spinlock.h and other
 * headers may reference after including paravirt.h.
 */
#ifndef _ASM_X86_PARAVIRT_H
#define _ASM_X86_PARAVIRT_H

/* paravirt.h normally includes paravirt_types.h which defines the
 * paravirt_patch_template structure. We don't need the full type system
 * for BPF compilation of lib/ code. */

/* Stub out paravirt-specific macros that spinlock.h or other callers use */
#define paravirt_set_cap() do {} while (0)
#define paravirt_arch_dup_mmap(oldmm, mm) do {} while (0)
#define paravirt_arch_exit_mmap(mm) do {} while (0)

/* native_* stubs for TLB operations referenced by spinlock/mmu code */
static inline void native_flush_tlb_local(void) {}
static inline void native_flush_tlb_global(void) {}
static inline void native_flush_tlb_one_user(unsigned long addr) {}

/* Stub for slow_down_io which is defined in paravirt.h */
static inline void slow_down_io(void) {}

/* default_banner stub */
static inline void x86_init_noop(void) {}
#define default_banner x86_init_noop

#endif /* _ASM_X86_PARAVIRT_H */
