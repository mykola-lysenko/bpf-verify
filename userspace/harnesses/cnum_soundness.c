// SPDX-License-Identifier: GPL-2.0-only
/*
 * Soundness fuzzer for the BPF verifier's circular-number (cnum) abstract
 * domain (kernel/bpf/cnum.c) -- the brand-new (2026) unified signed/unsigned
 * range tracker, far less battle-tested than tnum.
 *
 * A cnum{32,64} is an arc on the mod-2^N circle:
 *   gamma(c) = { c.base, c.base+1, ..., c.base+c.size }  (mod 2^N)
 * An abstract operation cnum_OP is SOUND iff it over-approximates the concrete
 * operation: for all x in gamma(a), y in gamma(b), OP(x,y) is in
 * gamma(cnum_OP(a,b)). An unsound op would let the verifier conclude a register
 * cannot hold a value it actually can -- a real, reportable verifier bug
 * (mis-accepted programs / miscompiled bounds).
 *
 * We generate SMALL arcs so gamma() is enumerable EXHAUSTIVELY, biasing base
 * toward the signed/unsigned boundaries (0, U*_MAX, S*_MAX, S*_MIN) where the
 * circular wrap logic is subtlest. Each iteration is then a complete soundness
 * proof for its (a, b) pair in the small-arc regime.
 *
 * Checked per op: contains self-consistency, add, negate, intersect (a∩b ⊆ r),
 * is_subset (both directions), and the umin/umax/smin/smax range projections.
 */
#include "fuzz.h"

#include KCNUM_SRC

typedef unsigned long long ull;

#define MAXSIZE 16   /* max arc length; gamma has size+1 elements */

/* ------------------------------------------------------------------ 32-bit */
static const u32 BND32[] = {
	0, 1, 0x7fffffffu, 0x80000000u, 0xffffffffu, 0x7ffffffeu, 0x80000001u,
};

static struct cnum32 gen32(struct fuzz_input *in)
{
	u32 base;
	if (fuzz_u64(in) & 1) {
		base = BND32[fuzz_range(in, 0, ARRAY_SIZE(BND32) - 1)]
		     + (u32)fuzz_range(in, 0, 2 * MAXSIZE) - MAXSIZE;
	} else {
		base = (u32)fuzz_u64(in);
	}
	return (struct cnum32){ .base = base,
				.size = (u32)fuzz_range(in, 0, MAXSIZE) };
}

#define FAIL(fmt, ...) do { snprintf(msg, msglen, fmt, ##__VA_ARGS__); return 1; } while (0)

static int check32(struct fuzz_input *in, char *msg, size_t msglen)
{
	struct cnum32 a = gen32(in), b = gen32(in);

	/* Self-consistency: every enumerated member is contained (validates our
	 * gamma() and catches a broken contains()). */
	for (u32 i = 0; i <= a.size; i++)
		if (!cnum32_contains(a, a.base + i))
			FAIL("32 contains miss: a={%u,%u} v=%u", a.base, a.size, a.base + i);

	/* add: OP(x,y)=x+y must land in gamma(cnum32_add(a,b)). */
	struct cnum32 r = cnum32_add(a, b);
	for (u32 i = 0; i <= a.size; i++)
		for (u32 j = 0; j <= b.size; j++)
			if (!cnum32_contains(r, (a.base + i) + (b.base + j)))
				FAIL("32 add unsound: a={%u,%u} b={%u,%u} x+y=%u r={%u,%u}",
				     a.base, a.size, b.base, b.size,
				     (a.base + i) + (b.base + j), r.base, r.size);

	/* negate: -x must land in gamma(cnum32_negate(a)). */
	struct cnum32 n = cnum32_negate(a);
	for (u32 i = 0; i <= a.size; i++)
		if (!cnum32_contains(n, (u32)(-(u32)(a.base + i))))
			FAIL("32 negate unsound: a={%u,%u} -x=%u n={%u,%u}",
			     a.base, a.size, (u32)(-(u32)(a.base + i)), n.base, n.size);

	/* intersect: gamma(a) ∩ gamma(b) ⊆ gamma(cnum32_intersect(a,b)). */
	struct cnum32 x = cnum32_intersect(a, b);
	for (u32 i = 0; i <= a.size; i++) {
		u32 v = a.base + i;
		if (cnum32_contains(b, v) && !cnum32_contains(x, v))
			FAIL("32 intersect unsound: a={%u,%u} b={%u,%u} v=%u x={%u,%u}",
			     a.base, a.size, b.base, b.size, v, x.base, x.size);
	}

	/* is_subset(outer, inner): claims gamma(inner) ⊆ gamma(outer). Verify both
	 * directions against enumeration. */
	int claim = cnum32_is_subset(a, b);   /* b ⊆ a ? */
	int truth = 1;
	for (u32 i = 0; i <= b.size; i++)
		if (!cnum32_contains(a, b.base + i)) { truth = 0; break; }
	if (claim && !truth)
		FAIL("32 is_subset unsound (claimed b⊆a, false): a={%u,%u} b={%u,%u}",
		     a.base, a.size, b.base, b.size);
	if (!claim && truth)
		FAIL("32 is_subset imprecise (missed b⊆a): a={%u,%u} b={%u,%u}",
		     a.base, a.size, b.base, b.size);

	/* Range projections: every member lies within the claimed u/s bounds. */
	u32 umn = cnum32_umin(a), umx = cnum32_umax(a);
	s32 smn = cnum32_smin(a), smx = cnum32_smax(a);
	for (u32 i = 0; i <= a.size; i++) {
		u32 v = a.base + i;
		if (v < umn || v > umx)
			FAIL("32 umin/umax unsound: a={%u,%u} v=%u [%u,%u]",
			     a.base, a.size, v, umn, umx);
		if ((s32)v < smn || (s32)v > smx)
			FAIL("32 smin/smax unsound: a={%u,%u} v=%d [%d,%d]",
			     a.base, a.size, (s32)v, smn, smx);
	}
	return 0;
}

/* ------------------------------------------------------------------ 64-bit */
static const u64 BND64[] = {
	0, 1, 0x7fffffffffffffffull, 0x8000000000000000ull, 0xffffffffffffffffull,
};

static struct cnum64 gen64(struct fuzz_input *in)
{
	u64 base;
	if (fuzz_u64(in) & 1)
		base = BND64[fuzz_range(in, 0, ARRAY_SIZE(BND64) - 1)]
		     + (u64)fuzz_range(in, 0, 2 * MAXSIZE) - MAXSIZE;
	else
		base = fuzz_u64(in);
	return (struct cnum64){ .base = base,
				.size = (u64)fuzz_range(in, 0, MAXSIZE) };
}

static int check64(struct fuzz_input *in, char *msg, size_t msglen)
{
	struct cnum64 a = gen64(in), b = gen64(in);

	for (u64 i = 0; i <= a.size; i++)
		if (!cnum64_contains(a, a.base + i))
			FAIL("64 contains miss: a={%llu,%llu}", (ull)a.base, (ull)a.size);

	struct cnum64 r = cnum64_add(a, b);
	for (u64 i = 0; i <= a.size; i++)
		for (u64 j = 0; j <= b.size; j++)
			if (!cnum64_contains(r, (a.base + i) + (b.base + j)))
				FAIL("64 add unsound: a={%llu,%llu} b={%llu,%llu} r={%llu,%llu}",
				     (ull)a.base, (ull)a.size, (ull)b.base, (ull)b.size,
				     (ull)r.base, (ull)r.size);

	struct cnum64 n = cnum64_negate(a);
	for (u64 i = 0; i <= a.size; i++)
		if (!cnum64_contains(n, (u64)(-(u64)(a.base + i))))
			FAIL("64 negate unsound: a={%llu,%llu} n={%llu,%llu}",
			     (ull)a.base, (ull)a.size, (ull)n.base, (ull)n.size);

	struct cnum64 x = cnum64_intersect(a, b);
	for (u64 i = 0; i <= a.size; i++) {
		u64 v = a.base + i;
		if (cnum64_contains(b, v) && !cnum64_contains(x, v))
			FAIL("64 intersect unsound: a={%llu,%llu} b={%llu,%llu} x={%llu,%llu}",
			     (ull)a.base, (ull)a.size, (ull)b.base, (ull)b.size,
			     (ull)x.base, (ull)x.size);
	}

	int claim = cnum64_is_subset(a, b);
	int truth = 1;
	for (u64 i = 0; i <= b.size; i++)
		if (!cnum64_contains(a, b.base + i)) { truth = 0; break; }
	if (claim && !truth)
		FAIL("64 is_subset unsound: a={%llu,%llu} b={%llu,%llu}",
		     (ull)a.base, (ull)a.size, (ull)b.base, (ull)b.size);
	if (!claim && truth)
		FAIL("64 is_subset imprecise: a={%llu,%llu} b={%llu,%llu}",
		     (ull)a.base, (ull)a.size, (ull)b.base, (ull)b.size);

	u64 umn = cnum64_umin(a), umx = cnum64_umax(a);
	s64 smn = cnum64_smin(a), smx = cnum64_smax(a);
	for (u64 i = 0; i <= a.size; i++) {
		u64 v = a.base + i;
		if (v < umn || v > umx)
			FAIL("64 umin/umax unsound: a={%llu,%llu}", (ull)a.base, (ull)a.size);
		if ((s64)v < smn || (s64)v > smx)
			FAIL("64 smin/smax unsound: a={%llu,%llu}", (ull)a.base, (ull)a.size);
	}
	return 0;
}

int fuzz_case(struct fuzz_input *in, char *msg, size_t msglen)
{
	int rc = check32(in, msg, msglen);
	if (rc)
		return rc;
	return check64(in, msg, msglen);
}

const char *fuzz_name = "cnum_soundness";
