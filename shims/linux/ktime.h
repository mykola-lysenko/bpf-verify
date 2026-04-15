/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: linux/ktime.h
 *
 * The real linux/ktime.h defines ktime_divns() using s64/s64 (signed division)
 * on 64-bit systems. The BPF backend cannot select the sdiv instruction.
 *
 * Strategy: rename ktime_divns, ktime_to_us, ktime_to_ms, ktime_us_delta,
 * ktime_ms_delta to unused symbols before including the real header. The real
 * header's function bodies compile as renamed (signed) functions that are
 * never called and get optimized away. After the include, provide BPF-safe
 * macro versions using unsigned (u64) division.
 *
 * Code that includes this shim (e.g. dim.c via linux/dim.h) will see the
 * BPF-safe macro versions for all ktime division functions.
 */
#ifndef _LINUX_KTIME_H

/* Step 1: Rename the signed-division functions before the real header. */
#define ktime_divns    __bpf_ktime_divns_signed_unused
#define ktime_to_us    __bpf_ktime_to_us_signed_unused
#define ktime_to_ms    __bpf_ktime_to_ms_signed_unused
#define ktime_us_delta __bpf_ktime_us_delta_signed_unused
#define ktime_ms_delta __bpf_ktime_ms_delta_signed_unused

/* Step 2: Include the real header (functions compiled with renamed identifiers). */
#include_next <linux/ktime.h>

/* Step 3: Undefine renames and provide BPF-safe unsigned versions. */
#undef ktime_divns
#undef ktime_to_us
#undef ktime_to_ms
#undef ktime_us_delta
#undef ktime_ms_delta

#define ktime_divns(kt, div) \
((s64)((u64)(ktime_t)(kt) / (u64)(s64)(div)))

#define ktime_to_us(kt) \
ktime_divns((kt), NSEC_PER_USEC)

#define ktime_to_ms(kt) \
ktime_divns((kt), NSEC_PER_MSEC)

#define ktime_us_delta(later, earlier) \
ktime_to_us(ktime_sub((later), (earlier)))

#define ktime_ms_delta(later, earlier) \
ktime_to_ms(ktime_sub((later), (earlier)))

#endif /* _LINUX_KTIME_H */
