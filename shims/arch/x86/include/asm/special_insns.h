/* BPF shim: asm/special_insns.h
 * x86 special_insns.h uses RDPKRU/WRPKRU/CLAC/STAC inline asm not valid in BPF.
 * Provide stubs - these instructions are not needed for lib/ targets.
 */
#ifndef _ASM_X86_SPECIAL_INSNS_H
#define _ASM_X86_SPECIAL_INSNS_H

#include <linux/types.h>

/* CR register stubs */
static __always_inline unsigned long native_read_cr0(void) { return 0; }
static __always_inline void native_write_cr0(unsigned long val) {}
static __always_inline unsigned long native_read_cr2(void) { return 0; }
static __always_inline void native_write_cr2(unsigned long val) {}
static __always_inline unsigned long native_read_cr3(void) { return 0; }
static __always_inline void native_write_cr3(unsigned long val) {}
static __always_inline unsigned long native_read_cr4(void) { return 0; }
static __always_inline void native_write_cr4(unsigned long val) {}

/* PKRU stubs */
static __always_inline u32 rdpkru(void) { return 0; }
static __always_inline void wrpkru(u32 pkru) {}

/* CLAC/STAC stubs */
static __always_inline void clac(void) {}
static __always_inline void stac(void) {}

/* DR register stubs */
static __always_inline unsigned long native_get_debugreg(int regno) { return 0; }
static __always_inline void native_set_debugreg(int regno, unsigned long val) {}


#endif /* _ASM_X86_SPECIAL_INSNS_H */
