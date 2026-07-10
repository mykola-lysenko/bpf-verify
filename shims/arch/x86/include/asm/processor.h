/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: asm/processor.h
 *
 * The real x86 processor.h defines task/thread CPU state and many helpers using
 * privileged or performance-related inline asm. Keep the small API surface that
 * generic headers expect, and model CPU instructions as no-ops.
 */
#ifndef _ASM_X86_PROCESSOR_H
#define _ASM_X86_PROCESSOR_H

#include <linux/cache.h>
#include <linux/types.h>
#include <asm/page.h>
#include <asm/processor-flags.h>

struct task_struct;
struct mm_struct;
struct pt_regs;

#define NET_IP_ALIGN 0
#define HBP_NUM 4
#define ARCH_MIN_TASKALIGN 0
#define ARCH_MIN_MMSTRUCT_ALIGN 0
#define ARCH_HAS_PREFETCHW

struct cpuinfo_x86 {
	u8 x86;
	u8 x86_vendor;
	u8 x86_model;
	u8 x86_cache_bits;
	int x86_cache_alignment;
};

#define X86_VENDOR_INTEL 0
#define X86_VENDOR_AMD 2
#define X86_VENDOR_UNKNOWN 0xff

#define cache_line_size() 64
#define cpu_data(cpu) ((struct cpuinfo_x86){ 0 })

static inline unsigned long l1tf_pfn_limit(void)
{
	return 0;
}

struct thread_struct {
	unsigned long sp;
	unsigned long fsbase;
	unsigned long gsbase;
};

#define INIT_THREAD { .sp = 0 }

static inline unsigned long read_cr3_pa(void) { return 0; }
static inline unsigned long native_read_cr3_pa(void) { return 0; }
static inline void load_cr3(void *pgdir) { (void)pgdir; }
static inline void load_sp0(unsigned long sp0) { (void)sp0; }
static inline unsigned long current_top_of_stack(void) { return 0; }
static inline bool on_thread_stack(void) { return false; }
static inline void current_save_fsgs(void) { }

static inline void rep_nop(void) { }
static inline void cpu_relax(void) { }
static inline void prefetch(const void *x) { (void)x; }
static inline void prefetchw(const void *x) { (void)x; }

#define task_top_of_stack(task) 0UL
#define task_pt_regs(task) ((struct pt_regs *)0)
#define KSTK_EIP(task) 0UL
#define KSTK_ESP(task) 0UL

static inline unsigned long __get_wchan(struct task_struct *p)
{
	(void)p;
	return 0;
}

#define HAVE_ARCH_PICK_MMAP_LAYOUT 1
#define TASK_UNMAPPED_BASE 0UL

static inline int get_tsc_mode(unsigned long adr)
{
	(void)adr;
	return 0;
}

static inline int set_tsc_mode(unsigned int val)
{
	(void)val;
	return 0;
}

static inline u32 per_cpu_llc_id(unsigned int cpu)
{
	(void)cpu;
	return 0;
}

#endif /* _ASM_X86_PROCESSOR_H */
