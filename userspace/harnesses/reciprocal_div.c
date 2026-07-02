// SPDX-License-Identifier: GPL-2.0-only
/*
 * Userspace differential fuzzer for reciprocal_div.
 *
 * Property: for every 32-bit dividend a and divisor d >= 1,
 *   reciprocal_divide(a, reciprocal_value(d)) == a / d
 * (the fast invariant-divisor multiply must equal real division).
 *
 * This is a known-good target (the kernel ships test_reciprocal_div), so it
 * also serves to confirm the framework produces no false positives.
 *
 * The real reciprocal_value() lives in lib/math/reciprocal_div.c; we copy the
 * one-line inline reciprocal_divide() and the value computation shape from the
 * kernel header so the harness is self-contained, and cross-check the copy
 * against the kernel source in userspace/run.sh's drift note.
 */
#include "fuzz.h"

/* From include/linux/reciprocal_div.h (verbatim). */
struct reciprocal_value {
	u32 m;
	u8 sh1, sh2;
};

static inline u32 reciprocal_divide(u32 a, struct reciprocal_value R)
{
	u32 t = (u32)(((u64)a * R.m) >> 32);
	return (t + ((a - t) >> R.sh1)) >> R.sh2;
}

/* From lib/math/reciprocal_div.c (verbatim body). */
static struct reciprocal_value reciprocal_value(u32 d)
{
	struct reciprocal_value R;
	u64 m;
	int l;

	l = fls(d - 1);
	m = ((1ULL << 32) * ((1ULL << l) - d));
	do_div(m, d);
	++m;
	R.m = (u32)m;
	R.sh1 = min(l, 1);
	R.sh2 = max(l - 1, 0);

	return R;
}

int fuzz_case(struct fuzz_input *in, char *msg, size_t msglen)
{
	u32 a = (u32)fuzz_u64(in);
	u32 d = (u32)fuzz_u64(in);
	if (d == 0)
		d = 1; /* divisor must be >= 1 */

	struct reciprocal_value R = reciprocal_value(d);
	u32 fast = reciprocal_divide(a, R);
	u32 real = a / d;
	if (fast != real) {
		snprintf(msg, msglen,
			 "reciprocal_divide(a=%u, R(d=%u)) = %u, but a/d = %u",
			 a, d, fast, real);
		return 1;
	}
	return 0;
}

const char *fuzz_name = "reciprocal_div";
