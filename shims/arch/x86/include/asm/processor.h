/* BPF shim: asm/processor.h
 * x86 processor.h uses inline assembly and x86-specific constructs.
 * Provide minimal stubs for BPF compilation.
 */
#ifndef _ASM_X86_PROCESSOR_H
#define _ASM_X86_PROCESSOR_H

#include <linux/types.h>
#include <asm/cpufeature.h>
#include <asm/page.h>
#include <asm/pgtable_types.h>
#include <asm/special_insns.h>

/* CPU feature stubs */
#define cpu_has(c, bit)		0
#define boot_cpu_has(bit)	0
#define this_cpu_has(bit)	0

/* Idle/relax stubs (native_halt is in irqflags.h) */
static inline void cpu_relax(void) {}
static inline void rep_nop(void) {}

/* Cache line size */
#define cache_line_size()	64

/* Stack canary stub */
struct stack_canary {
	char __pad[20];
	unsigned long canary;
};

/* Thread info stubs */
#define THREAD_SIZE_ORDER	2

/* cpuinfo_x86 stub - minimal */
struct cpuinfo_x86 {
	unsigned char	x86;
	unsigned char	x86_vendor;
	unsigned char	x86_model;
	unsigned char	x86_stepping;
	int		x86_tlbsize;
	unsigned int	x86_virt_bits;
	unsigned int	x86_phys_bits;
	unsigned int	x86_capability[21];
	char		x86_vendor_id[16];
	char		x86_model_id[64];
	unsigned int	x86_cache_size;
	int		x86_cache_alignment;
	int		x86_power;
	unsigned long	loops_per_jiffy;
};

extern struct cpuinfo_x86 boot_cpu_data;

/* MSR stubs */
static inline unsigned long long native_read_msr(unsigned int msr) { return 0; }
static inline void native_write_msr(unsigned int msr, unsigned low, unsigned high) {}

#define read_cr0()	native_read_cr0()
#define read_cr2()	native_read_cr2()
#define read_cr3()	native_read_cr3()
#define read_cr4()	native_read_cr4()
#define write_cr0(x)	native_write_cr0(x)
#define write_cr2(x)	native_write_cr2(x)
#define write_cr4(x)	native_write_cr4(x)

/* CPUID stub */
static inline void cpuid(unsigned int op,
	unsigned int *eax, unsigned int *ebx,
	unsigned int *ecx, unsigned int *edx)
{
	*eax = *ebx = *ecx = *edx = 0;
}

/* Per-CPU current task */
struct task_struct;
extern struct task_struct *current;

/* thread_struct is the arch-specific per-thread CPU state.
 * sched.h:1642 embeds it in struct task_struct.
 * Provide a minimal stub so task_struct can be defined without
 * pulling in the full x86 processor.h (which has inline assembly). */
struct thread_struct {
	unsigned long		sp;		/* kernel stack pointer */
	unsigned long		ip;		/* instruction pointer */
	unsigned long		flags;		/* thread flags */
	unsigned long		cr2;		/* page fault address */
	unsigned long		trap_nr;	/* trap number */
	unsigned long		error_code;	/* trap error code */
};

#endif /* _ASM_X86_PROCESSOR_H */
