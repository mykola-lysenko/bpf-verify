// SPDX-License-Identifier: GPL-2.0-only
/* BPF shim: lib/math/polynomial.c
 * Stripped module.h/export.h; the function is pure integer math.
 * Signed divisions replaced with unsigned (BPF lacks sdiv). */

#include <linux/polynomial.h>

static inline long bpf_sdiv_long(long a, long b)
{
	int neg = 0;
	unsigned long ua, ub, result;

	if (a < 0) { ua = (unsigned long)-a; neg ^= 1; } else { ua = (unsigned long)a; }
	if (b < 0) { ub = (unsigned long)-b; neg ^= 1; } else { ub = (unsigned long)b; }
	result = ua / ub;
	return neg ? -(long)result : (long)result;
}

static inline long bpf_smod_long(long a, long b)
{
	return a - bpf_sdiv_long(a, b) * b;
}

static inline long bpf_mult_frac(long x, long n, long d)
{
	long q = bpf_sdiv_long(x, d);
	long r = bpf_smod_long(x, d);
	return q * n + bpf_sdiv_long(r * n, d);
}

long polynomial_calc(const struct polynomial *poly, long data)
{
	const struct polynomial_term *term = poly->terms;
	long total_divider = poly->total_divider ?: 1;
	long tmp, ret = 0;
	int deg;

	do {
		tmp = term->coef;
		for (deg = 0; deg < term->deg; ++deg)
			tmp = bpf_mult_frac(tmp, data, term->divider);
		ret += bpf_sdiv_long(tmp, term->divider_leftover);
	} while ((term++)->deg);

	return bpf_sdiv_long(ret, total_divider);
}
