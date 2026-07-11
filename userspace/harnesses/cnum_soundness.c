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
 * Ops checked: contains self-consistency, add, negate, intersect (a∩b ⊆ r),
 * is_subset (both directions), umin/umax/smin/smax projections, the range
 * constructors (from_srange) and refinements (intersect_with_urange/srange),
 * and -- the highest-EV part -- the 32/64-bit reconciliation helpers
 * (cnum32_from_cnum64 narrowing, cnum64_cnum32_intersect subreg refinement),
 * which are historically the buggiest corner of verifier value tracking.
 */
#include "fuzz.h"

#include KCNUM_SRC

typedef unsigned long long ull;

#define MAXSIZE 16   /* max arc length; gamma has size+1 elements */

#define FAIL(fmt, ...) do { snprintf(msg, msglen, fmt, ##__VA_ARGS__); return 1; } while (0)

/* ------------------------------------------------------------------ 32-bit */
static const u32 BND32[] = {
	0, 1, 0x7fffffffu, 0x80000000u, 0xffffffffu, 0x7ffffffeu, 0x80000001u,
};

/* A value biased toward the wrap boundaries (base/range endpoints live here). */
static u32 pick32(struct fuzz_input *in)
{
	if (fuzz_u64(in) & 1)
		return BND32[fuzz_range(in, 0, ARRAY_SIZE(BND32) - 1)]
		     + (u32)fuzz_range(in, 0, 2 * MAXSIZE) - MAXSIZE;
	return (u32)fuzz_u64(in);
}

static struct cnum32 gen32(struct fuzz_input *in)
{
	return (struct cnum32){ .base = pick32(in),
				.size = (u32)fuzz_range(in, 0, MAXSIZE) };
}

static int check32(struct fuzz_input *in, char *msg, size_t msglen)
{
	struct cnum32 a = gen32(in), b = gen32(in);

	/* Self-consistency: every enumerated member is contained. */
	for (u32 i = 0; i <= a.size; i++)
		if (!cnum32_contains(a, a.base + i))
			FAIL("32 contains miss: a={%u,%u} v=%u", a.base, a.size, a.base + i);

	/* add / negate / intersect. */
	struct cnum32 r = cnum32_add(a, b);
	for (u32 i = 0; i <= a.size; i++)
		for (u32 j = 0; j <= b.size; j++)
			if (!cnum32_contains(r, (a.base + i) + (b.base + j)))
				FAIL("32 add unsound: a={%u,%u} b={%u,%u} x+y=%u r={%u,%u}",
				     a.base, a.size, b.base, b.size,
				     (a.base + i) + (b.base + j), r.base, r.size);

	struct cnum32 n = cnum32_negate(a);
	for (u32 i = 0; i <= a.size; i++)
		if (!cnum32_contains(n, (u32)(-(u32)(a.base + i))))
			FAIL("32 negate unsound: a={%u,%u} -x=%u n={%u,%u}",
			     a.base, a.size, (u32)(-(u32)(a.base + i)), n.base, n.size);

	struct cnum32 x = cnum32_intersect(a, b);
	for (u32 i = 0; i <= a.size; i++) {
		u32 v = a.base + i;
		if (cnum32_contains(b, v) && !cnum32_contains(x, v))
			FAIL("32 intersect unsound: a={%u,%u} b={%u,%u} v=%u x={%u,%u}",
			     a.base, a.size, b.base, b.size, v, x.base, x.size);
	}

	/* is_subset(a, b): claims gamma(b) ⊆ gamma(a); check both directions. */
	int claim = cnum32_is_subset(a, b);
	int truth = 1;
	for (u32 i = 0; i <= b.size; i++)
		if (!cnum32_contains(a, b.base + i)) { truth = 0; break; }
	if (claim && !truth)
		FAIL("32 is_subset unsound (claimed b⊆a, false): a={%u,%u} b={%u,%u}",
		     a.base, a.size, b.base, b.size);
	if (!claim && truth)
		FAIL("32 is_subset imprecise (missed b⊆a): a={%u,%u} b={%u,%u}",
		     a.base, a.size, b.base, b.size);

	/* Range projections. */
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

	/* from_srange: every signed value in [lo,hi] must be contained. */
	{
		s32 lo = (s32)pick32(in);
		s32 hi = lo + (s32)fuzz_range(in, 0, MAXSIZE);
		struct cnum32 c = cnum32_from_srange(lo, hi);
		for (s32 s = lo;; s++) {
			if (!cnum32_contains(c, (u32)s))
				FAIL("32 from_srange unsound: [%d,%d] s=%d c={%u,%u}",
				     lo, hi, s, c.base, c.size);
			if (s == hi) break;
		}
	}

	/* intersect_with_urange: no member of gamma(a) ∩ [lo,hi] may be dropped. */
	{
		u32 lo = pick32(in);
		u32 hi = lo + (u32)fuzz_range(in, 0, 4 * MAXSIZE);   /* lo<=hi (no wrap) */
		struct cnum32 dst = a;
		cnum32_intersect_with_urange(&dst, lo, hi);
		for (u32 i = 0; i <= a.size; i++) {
			u32 v = a.base + i;
			if (v >= lo && v <= hi && !cnum32_contains(dst, v))
				FAIL("32 intersect_with_urange dropped: a={%u,%u} [%u,%u] v=%u dst={%u,%u}",
				     a.base, a.size, lo, hi, v, dst.base, dst.size);
		}
	}

	/* intersect_with_srange: signed variant. */
	{
		s32 lo = (s32)pick32(in);
		s32 hi = lo + (s32)fuzz_range(in, 0, 4 * MAXSIZE);
		struct cnum32 dst = a;
		cnum32_intersect_with_srange(&dst, lo, hi);
		for (u32 i = 0; i <= a.size; i++) {
			s32 v = (s32)(a.base + i);
			if (v >= lo && v <= hi && !cnum32_contains(dst, (u32)v))
				FAIL("32 intersect_with_srange dropped: a={%u,%u} [%d,%d] v=%d dst={%u,%u}",
				     a.base, a.size, lo, hi, v, dst.base, dst.size);
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ 64-bit */
static const u64 BND64[] = {
	0, 1, 0x7fffffffffffffffull, 0x8000000000000000ull, 0xffffffffffffffffull,
};

static u64 pick64(struct fuzz_input *in)
{
	if (fuzz_u64(in) & 1)
		return BND64[fuzz_range(in, 0, ARRAY_SIZE(BND64) - 1)]
		     + (u64)fuzz_range(in, 0, 2 * MAXSIZE) - MAXSIZE;
	return fuzz_u64(in);
}

static struct cnum64 gen64(struct fuzz_input *in)
{
	return (struct cnum64){ .base = pick64(in),
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

	{
		s64 lo = (s64)pick64(in);
		s64 hi = lo + (s64)fuzz_range(in, 0, MAXSIZE);
		struct cnum64 c = cnum64_from_srange(lo, hi);
		for (s64 s = lo;; s++) {
			if (!cnum64_contains(c, (u64)s))
				FAIL("64 from_srange unsound: [%lld,%lld] s=%lld",
				     (long long)lo, (long long)hi, (long long)s);
			if (s == hi) break;
		}
	}
	{
		u64 lo = pick64(in);
		u64 hi = lo + (u64)fuzz_range(in, 0, 4 * MAXSIZE);
		struct cnum64 dst = a;
		cnum64_intersect_with_urange(&dst, lo, hi);
		for (u64 i = 0; i <= a.size; i++) {
			u64 v = a.base + i;
			if (v >= lo && v <= hi && !cnum64_contains(dst, v))
				FAIL("64 intersect_with_urange dropped: a={%llu,%llu} v=%llu",
				     (ull)a.base, (ull)a.size, (ull)v);
		}
	}
	{
		s64 lo = (s64)pick64(in);
		s64 hi = lo + (s64)fuzz_range(in, 0, 4 * MAXSIZE);
		struct cnum64 dst = a;
		cnum64_intersect_with_srange(&dst, lo, hi);
		for (u64 i = 0; i <= a.size; i++) {
			s64 v = (s64)(a.base + i);
			if (v >= lo && v <= hi && !cnum64_contains(dst, (u64)v))
				FAIL("64 intersect_with_srange dropped: a={%llu,%llu} v=%lld",
				     (ull)a.base, (ull)a.size, (long long)v);
		}
	}
	return 0;
}

/* ------------------------------------------ 32/64-bit reconciliation (mixed) */
static int check_mixed(struct fuzz_input *in, char *msg, size_t msglen)
{
	struct cnum64 c = gen64(in);

	/* cnum32_from_cnum64: narrowing. Every low-32-bits of a 64-bit member must
	 * be contained in the 32-bit result. An over-narrow result would let the
	 * verifier drop a valid 32-bit subregister value -- a real soundness bug. */
	struct cnum32 nc = cnum32_from_cnum64(c);
	for (u64 i = 0; i <= c.size; i++) {
		u32 lo = (u32)(c.base + i);
		if (!cnum32_contains(nc, lo))
			FAIL("from_cnum64 unsound: c={%llu,%llu} lo32=%u nc={%u,%u}",
			     (ull)c.base, (ull)c.size, lo, nc.base, nc.size);
	}

	/* cnum64_cnum32_intersect: refine a 64-bit range with a 32-bit subreg
	 * constraint. Any 64-bit member whose low 32 bits satisfy b must survive. */
	struct cnum32 b = gen32(in);
	struct cnum64 r = cnum64_cnum32_intersect(c, b);
	for (u64 i = 0; i <= c.size; i++) {
		u64 v = c.base + i;
		if (cnum32_contains(b, (u32)v) && !cnum64_contains(r, v))
			FAIL("cnum32_intersect unsound: c={%llu,%llu} b={%u,%u} v=%llu r={%llu,%llu}",
			     (ull)c.base, (ull)c.size, b.base, b.size, (ull)v,
			     (ull)r.base, (ull)r.size);
	}
	return 0;
}

int fuzz_case(struct fuzz_input *in, char *msg, size_t msglen)
{
	int rc = check32(in, msg, msglen);
	if (rc)
		return rc;
	rc = check64(in, msg, msglen);
	if (rc)
		return rc;
	return check_mixed(in, msg, msglen);
}

const char *fuzz_name = "cnum_soundness";
