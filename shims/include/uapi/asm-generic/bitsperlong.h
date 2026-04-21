/* BPF shim: override x86 uapi/asm/bitsperlong.h
 * x86 defines __BITS_PER_LONG as 64 only for 64-bit userspace.
 * For BPF target (which is always 64-bit), we need __BITS_PER_LONG=64.
 */
#ifndef __ASM_BITSPERLONG_H
#define __ASM_BITSPERLONG_H

#define __BITS_PER_LONG 64

#include <asm-generic/bitsperlong.h>

#endif /* __ASM_BITSPERLONG_H */
