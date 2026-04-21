/* BPF shim: asm/string.h
 * x86 asm/string.h includes asm/string_64.h which uses inline assembly
 * not valid in BPF. Redirect to our BPF-safe string_64.h shim.
 */
#ifndef _ASM_X86_STRING_H
#define _ASM_X86_STRING_H

/* Include our BPF-safe string_64.h shim directly */
#include <asm/string_64.h>

#endif /* _ASM_X86_STRING_H */
