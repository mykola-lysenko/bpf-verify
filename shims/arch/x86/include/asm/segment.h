/* BPF shim: asm/segment.h
 * x86 segment.h uses segment register and RDPID inline asm not valid in BPF.
 * Provide minimal stubs for the segment constants used by kernel lib/ code.
 */
#ifndef _ASM_X86_SEGMENT_H
#define _ASM_X86_SEGMENT_H

/* Segment selector constants needed by some headers */
#define __KERNEL_CS	0x10
#define __KERNEL_DS	0x18
#define __USER_CS	0x23
#define __USER_DS	0x2b
#define __KERNEL32_CS	0x08
#define __CPUNODE_SEG	0x00

/* VDSO CPU/node packing constants */
#define VDSO_CPUNODE_BITS	12
#define VDSO_CPUNODE_MASK	0xfff

/* Stub for vdso_getcpu - not meaningful in BPF */
static inline void vdso_read_cpunode(unsigned *cpu, unsigned *node)
{
	if (cpu)
		*cpu = 0;
	if (node)
		*node = 0;
}

#endif /* _ASM_X86_SEGMENT_H */
