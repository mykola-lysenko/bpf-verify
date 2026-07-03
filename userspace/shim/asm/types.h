#ifndef _SHIM_ASM_TYPES_H
#define _SHIM_ASM_TYPES_H
/* Block the kernel's asm/types.h -> int-ll64.h re-typedef of u64/s64 etc.;
 * khost.h already provides these as host-compatible types. */
#endif
