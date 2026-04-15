/* BPF shim: asm/msr.h
 * x86 msr.h uses RDMSR/WRMSR inline asm not valid in BPF.
 * Provide stubs - MSR access is not needed for lib/ targets.
 */
#ifndef _ASM_X86_MSR_H
#define _ASM_X86_MSR_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* MSR access stubs */
static __always_inline unsigned long long __rdmsr(unsigned int msr)
{
	return 0;
}

static __always_inline void __wrmsr(unsigned int msr, u32 low, u32 high)
{
}

#define rdmsr(msr, low, high)		do { (low) = 0; (high) = 0; } while (0)
#define wrmsr(msr, low, high)		do { } while (0)
#define rdmsrl(msr, val)		do { (val) = 0; } while (0)
#define wrmsrl(msr, val)		do { } while (0)
#define rdmsr_safe(msr, low, high)	({ (low) = 0; (high) = 0; 0; })
#define rdmsrl_safe(msr, val)		({ (val) = 0; 0; })
#define wrmsrl_safe(msr, val)		(0)
#define rdmsr_on_cpu(cpu, msr, low, high) do { (low) = 0; (high) = 0; } while (0)
#define wrmsr_on_cpu(cpu, msr, low, high) do { } while (0)

/* native_rdmsr/wrmsr stubs */
#define native_rdmsr(msr, val1, val2)	do { (val1) = 0; (val2) = 0; } while (0)
#define native_wrmsr(msr, low, high)	do { } while (0)
#define native_wrmsrl(msr, val)		do { } while (0)

#endif /* _ASM_X86_MSR_H */
