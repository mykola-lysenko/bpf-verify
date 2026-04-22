// SPDX-License-Identifier: GPL-2.0-only
/* BPF shim: lib/math/polynomial.c
 * Full copy required — BPF lacks sdiv, so all signed divisions
 * must be replaced with unsigned equivalents. */

#include <linux/math.h>
#include <linux/polynomial.h>

static __always_inline long __bpf_sdiv(long a, long b)
{
	int neg = 0;
	unsigned long ua, ub, r;
	if (a < 0) { ua = -a; neg ^= 1; } else { ua = a; }
	if (b < 0) { ub = -b; neg ^= 1; } else { ub = b; }
	r = ua / ub;
	return neg ? -(long)r : (long)r;
}

#undef mult_frac
#define mult_frac(x, n, d) ({				\
	typeof(x) q_ = __bpf_sdiv((x), (d));		\
	typeof(x) r_ = (x) - q_ * (d);			\
	q_ * (n) + __bpf_sdiv(r_ * (n), (d));		\
})

long polynomial_calc(const struct polynomial *poly, long data)
{
	const struct polynomial_term *term = poly->terms;
	long total_divider = poly->total_divider ?: 1;
	long tmp, ret = 0;
	int deg;

	do {
		tmp = term->coef;
		for (deg = 0; deg < term->deg; ++deg)
			tmp = mult_frac(tmp, data, term->divider);
		ret += __bpf_sdiv(tmp, term->divider_leftover);
	} while ((term++)->deg);

	return __bpf_sdiv(ret, total_divider);
}
