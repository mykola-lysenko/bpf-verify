/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: asm/cpufeature.h
 *
 * The real x86 cpufeature.h depends on generated feature masks and
 * alternative-instruction machinery. Harnesses only need feature predicates to
 * compile; model optional CPU features as unavailable.
 */
#ifndef _ASM_X86_CPUFEATURE_H
#define _ASM_X86_CPUFEATURE_H

#include <asm/cpufeatures.h>

struct cpuinfo_x86;

#define cpu_has(c, bit)			0
#define cpu_feature_enabled(bit)	0
#define boot_cpu_has(bit)		0
#define boot_cpu_has_bug(bit)		0
#define static_cpu_has(bit)		0
#define static_cpu_has_safe(bit)	0
#define static_cpu_has_bug(bit)		0
#define this_cpu_has(bit)		0

static inline void setup_force_cpu_cap(unsigned int bit) { (void)bit; }
static inline void setup_clear_cpu_cap(unsigned int bit) { (void)bit; }
static inline void clear_cpu_cap(struct cpuinfo_x86 *c, unsigned int bit)
{
	(void)c;
	(void)bit;
}

#endif /* _ASM_X86_CPUFEATURE_H */
