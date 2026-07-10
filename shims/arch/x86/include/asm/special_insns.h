/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: asm/special_insns.h
 *
 * The real x86 header is mostly privileged CPU instructions and cache-control
 * inline asm. Standalone verifier harnesses only need these APIs to compile;
 * model them as inert C helpers.
 */
#ifndef _ASM_X86_SPECIAL_INSNS_H
#define _ASM_X86_SPECIAL_INSNS_H

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>

static inline void native_write_cr0(unsigned long val) { (void)val; }
static inline unsigned long native_read_cr0(void) { return 0; }
static inline unsigned long native_read_cr2(void) { return 0; }
static inline void native_write_cr2(unsigned long val) { (void)val; }
static inline unsigned long __native_read_cr3(void) { return 0; }
static inline void native_write_cr3(unsigned long val) { (void)val; }
static inline unsigned long native_read_cr4(void) { return 0; }
static inline void native_write_cr4(unsigned long val) { (void)val; }

static inline u32 rdpkru(void) { return 0; }
static inline void wrpkru(u32 pkru) { (void)pkru; }

static inline void wbinvd(void) { }
static inline void wbnoinvd(void) { }

static inline unsigned long __read_cr4(void) { return native_read_cr4(); }
static inline unsigned long read_cr0(void) { return native_read_cr0(); }
static inline void write_cr0(unsigned long x) { native_write_cr0(x); }
static inline unsigned long read_cr2(void) { return native_read_cr2(); }
static inline void write_cr2(unsigned long x) { native_write_cr2(x); }
static inline unsigned long __read_cr3(void) { return __native_read_cr3(); }
static inline void write_cr3(unsigned long x) { native_write_cr3(x); }
static inline void __write_cr4(unsigned long x) { native_write_cr4(x); }

static inline void clflush(volatile void *p) { (void)p; }
static inline void clflushopt(volatile void *p) { (void)p; }
static inline void clwb(volatile void *p) { (void)p; }

#ifndef nop
#define nop() do { } while (0)
#endif

static inline void serialize(void) { }
static inline void movdir64b(void *dst, const void *src)
{
	(void)dst;
	(void)src;
}

static inline void movdir64b_io(void __iomem *dst, const void *src)
{
	(void)dst;
	(void)src;
}

static inline int enqcmds(void __iomem *dst, const void *src)
{
	(void)dst;
	(void)src;
	return -EAGAIN;
}

static inline void tile_release(void) { }

#endif /* __KERNEL__ */
#endif /* _ASM_X86_SPECIAL_INSNS_H */
