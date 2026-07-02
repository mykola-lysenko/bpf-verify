/* Block arch asm/checksum.h to prevent ip_fast_csum redefinition. */
#define _ASM_X86_CHECKSUM_H
#define _ASM_X86_CHECKSUM_64_H
#define _ASM_X86_CHECKSUM_32_H
#include <asm-generic/checksum.h>
/* Undefine the generic ip_fast_csum so lib/checksum.c can define it. */
#undef ip_fast_csum
