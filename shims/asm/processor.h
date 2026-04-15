/* BPF shim: asm/processor.h
 * x86 processor.h includes many headers with inline asm not valid in BPF.
 * Provide minimal stubs for the types and functions needed by lib/ targets.
 * NOTE: Do NOT include asm/cpufeatures.h here - it circularly includes processor.h.
 */
#ifndef _ASM_X86_PROCESSOR_H
#define _ASM_X86_PROCESSOR_H

#include <linux/types.h>
#include <asm/types.h>

/* Define NCAPINTS/NBUGINTS directly (from asm/cpufeatures.h) to avoid circular include */
#ifndef NCAPINTS
#define NCAPINTS	22	/* N 32-bit words worth of info */
#endif
#ifndef NBUGINTS
#define NBUGINTS	2	/* N 32-bit bug flags */
#endif

/* Minimal cpuinfo_x86 struct - only the fields used by cpufeature.h */
struct cpuinfo_x86 {
	__u8		x86;
	__u8		x86_vendor;
	__u8		x86_model;
	__u8		x86_stepping;
	int		x86_tlbsize;
	__u32		x86_capability[NCAPINTS + NBUGINTS];
	char		x86_vendor_id[16];
	char		x86_model_id[64];
	unsigned int	x86_cache_size;
	int		x86_cache_alignment;
	int		x86_cache_max_rmid;
	int		x86_cache_occ_scale;
	int		x86_cache_mbm_width_offset;
	int		x86_power;
	unsigned long	loops_per_jiffy;
	u64		ppin;
	u16		x86_max_cores;
	u16		apicid;
	u16		initial_apicid;
	u16		x86_clflush_size;
	u16		booted_cores;
	u16		phys_proc_id;
	u16		logical_proc_id;
	u16		cpu_core_id;
	u16		cpu_die_id;
	u16		logical_die_id;
	u16		cpu_index;
	bool		smt_active;
	u32		microcode;
	u8		x86_cache_bits;
	unsigned	initialized : 1;
};

extern struct cpuinfo_x86 boot_cpu_data;
extern struct cpuinfo_x86 __percpu *cpu_info;

/* native_cpuid stub */
static __always_inline void native_cpuid(unsigned int *eax, unsigned int *ebx,
					  unsigned int *ecx, unsigned int *edx)
{
	*eax = *ebx = *ecx = *edx = 0;
}

/* have_cpuid_p stub */
static inline int have_cpuid_p(void) { return 1; }

/* cpu_relax stub */
static __always_inline void cpu_relax(void) {}
static __always_inline void rep_nop(void) {}
static __always_inline void cpu_relax_lowlatency(void) {}

/* __cpuid stub */
static __always_inline void __cpuid(unsigned int *eax, unsigned int *ebx,
				     unsigned int *ecx, unsigned int *edx)
{
	native_cpuid(eax, ebx, ecx, edx);
}

/* Prefetch stubs */
static __always_inline void prefetch(const void *x) {}
static __always_inline void prefetchw(const void *x) {}
static __always_inline void prefetcht0(const void *x) {}
static __always_inline void prefetcht1(const void *x) {}
static __always_inline void prefetcht2(const void *x) {}
static __always_inline void prefetchnta(const void *x) {}

/* wbinvd stub */
static __always_inline void wbinvd(void) {}

/* TSC stubs */
static __always_inline u64 rdtsc(void) { return 0; }
static __always_inline u64 rdtsc_ordered(void) { return 0; }

/* IO stubs */
static __always_inline void native_io_delay(void) {}
static __always_inline void io_delay(void) {}

/* Halt stub */
static __always_inline void halt(void) {}

/* SWAPGS stub */
static __always_inline void native_swapgs(void) {}

/* Task size */
#define TASK_SIZE_MAX		((1UL << 47) - PAGE_SIZE)
#define DEFAULT_MAP_WINDOW	((1UL << 47) - PAGE_SIZE)

#endif /* _ASM_X86_PROCESSOR_H */
