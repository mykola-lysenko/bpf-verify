/* BPF shim: asm/cpufeature.h
 * x86 cpufeature.h uses asm goto with x86 inline assembly (ALTERNATIVE_TERNARY)
 * in _static_cpu_has() which is not valid in BPF context.
 *
 * This shim provides BPF-safe stubs:
 *  - All cpu_feature_enabled/static_cpu_has/boot_cpu_has return 0 (feature absent)
 *  - X86_FEATURE_* constants are provided via the real cpufeatures.h
 *  - cpu_has() checks boot_cpu_data.x86_capability[] (safe, no asm)
 */
#ifndef _ASM_X86_CPUFEATURE_H
#define _ASM_X86_CPUFEATURE_H

/* Include processor.h for cpuinfo_x86 struct and boot_cpu_data */
#include <asm/processor.h>

/* Include the real cpufeatures.h for X86_FEATURE_* constants */
#include <asm/cpufeatures.h>

/* DISABLED_MASK_BIT_SET: always 0 in BPF context (no disabled features) */
#define DISABLED_MASK_BIT_SET(bit) 0

/* cpu_has: check a specific feature bit in cpuinfo_x86.x86_capability */
#define cpu_has(c, bit) \
    !!((c)->x86_capability[(bit) >> 5] & (1 << ((bit) & 31)))

/* boot_cpu_has: check feature in boot_cpu_data */
#define boot_cpu_has(bit) cpu_has(&boot_cpu_data, bit)

/* static_cpu_has: BPF-safe version - always returns 0 (conservative) */
#define static_cpu_has(bit) (0)

/* cpu_feature_enabled: BPF-safe version */
#define cpu_feature_enabled(bit) \
    (__builtin_constant_p(bit) && DISABLED_MASK_BIT_SET(bit) ? 0 : static_cpu_has(bit))

/* cpu_has_bug, set_cpu_cap, clear_cpu_cap stubs */
#define cpu_has_bug(c, bit)     cpu_has(c, (bit))
#define set_cpu_bug(c, bit)     do {} while (0)
#define clear_cpu_bug(c, bit)   do {} while (0)
#define set_cpu_cap(c, bit)     do {} while (0)
#define clear_cpu_cap(c, bit)   do {} while (0)
#define setup_clear_cpu_cap(bit) do {} while (0)
#define setup_force_cpu_cap(bit) do {} while (0)
#define setup_force_cpu_bug(bit) do {} while (0)

/* boot_cpu_has_bug, static_cpu_has_bug */
#define boot_cpu_has_bug(bit)   cpu_has_bug(&boot_cpu_data, (bit))
#define static_cpu_has_bug(bit) static_cpu_has((bit))
#define boot_cpu_set_bug(bit)   set_cpu_cap(&boot_cpu_data, (bit))

/* cpu_have_feature */
#define cpu_have_feature boot_cpu_has

/* MAX_CPU_FEATURES */
#define MAX_CPU_FEATURES (NCAPINTS * 32)

/* cpu_caps_set/cleared stubs */
extern unsigned long cpu_caps_set[];
extern unsigned long cpu_caps_cleared[];

#endif /* _ASM_X86_CPUFEATURE_H */
