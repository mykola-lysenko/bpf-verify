/* BPF shim: asm/types.h
 * x86 doesn't provide asm/types.h directly; it uses asm-generic/int-ll64.h
 * via the Kbuild symlink mechanism. Provide the redirect here.
 */
#ifndef _ASM_TYPES_H
#define _ASM_TYPES_H
#include <uapi/asm-generic/types.h>
#endif
