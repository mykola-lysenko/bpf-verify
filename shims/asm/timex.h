/* BPF shim: asm/timex.h - x86 timex.h uses TSC inline asm */
#ifndef _ASM_X86_TIMEX_H
#define _ASM_X86_TIMEX_H
#include <linux/types.h>
typedef unsigned long long cycles_t;
static inline cycles_t get_cycles(void) { return 0; }
#define vxtime_lock()   do {} while (0)
#define vxtime_unlock() do {} while (0)
#endif
