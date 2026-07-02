// SPDX-License-Identifier: GPL-2.0-only
/*
 * Soundness fuzzer for the BPF verifier's tristate-number abstract domain
 * (kernel/bpf/tnum.c) -- the core of the verifier's value tracking.
 *
 * A tnum t = {value, mask} represents the set of concrete u64s
 *   gamma(t) = { z : (z & ~t.mask) == t.value }.
 * An abstract operation tnum_OP is SOUND iff it over-approximates the concrete
 * operation: for all a, b and all x in gamma(a), y in gamma(b),
 *   OP(x, y) is in gamma(tnum_OP(a, b)).
 * An unsound operation would let the verifier conclude a register cannot take
 * a value it actually can -- a real, reportable verifier bug (mis-accepted
 * programs / miscompiled bounds).
 *
 * We generate small tnums (few unknown bits) so gamma() can be enumerated
 * EXHAUSTIVELY, turning each fuzz iteration into a complete soundness proof for
 * that (a, b) pair. This is the standard way tnum soundness is checked
 * (cf. Vishwanathan et al., "Sound, Precise, and Fast Abstract Interpretation
 * with Tristate Numbers").
 */
#include "fuzz.h"

#include KTNUM_SRC

typedef unsigned long long ull;

/* z is a member of t iff its known bits match t.value. */
static inline int tnum_member(u64 z, struct tnum t)
{
	return (z & ~t.mask) == t.value;
}

/* Build a tnum with at most `maxbits` unknown bits, drawn from the input. */
static struct tnum gen_tnum(struct fuzz_input *in, int maxbits)
{
	u64 mask = 0;
	int nbits = (int)fuzz_range(in, 0, maxbits);
	for (int i = 0; i < nbits; i++)
		mask |= 1ULL << (fuzz_u64(in) & 63);
	u64 value = fuzz_u64(in) & ~mask; /* known bits must be 0 under mask */
	return TNUM(value, mask);
}

/* Enumerate all members of t into out[] (caller guarantees capacity 1<<popcount).
 * Returns the count. */
static int enumerate(struct tnum t, u64 *out, int cap)
{
	int bitpos[16], nb = 0;
	for (int i = 0; i < 64 && nb < 16; i++)
		if (t.mask & (1ULL << i))
			bitpos[nb++] = i;
	if (nb > 12)
		return -1; /* too many members; skip (gen_tnum bounds this) */
	int n = 1 << nb;
	if (n > cap)
		return -1;
	for (int s = 0; s < n; s++) {
		u64 z = t.value;
		for (int b = 0; b < nb; b++)
			if (s & (1 << b))
				z |= 1ULL << bitpos[b];
		out[s] = z;
	}
	return n;
}

/* Check one binary op for soundness over all member pairs. */
static int check_binop(const char *name, struct tnum ra, struct tnum a,
		       struct tnum b, u64 *am, int an, u64 *bm, int bn,
		       u64 (*concrete)(u64, u64), char *msg, size_t msglen)
{
	for (int i = 0; i < an; i++)
		for (int j = 0; j < bn; j++) {
			u64 r = concrete(am[i], bm[j]);
			if (!tnum_member(r, ra)) {
				snprintf(msg, msglen,
					 "UNSOUND tnum_%s: a={%#llx,%#llx} b={%#llx,%#llx} "
					 "x=%#llx y=%#llx -> %#llx NOT in result {%#llx,%#llx}",
					 name,
					 (ull)a.value, (ull)a.mask, (ull)b.value, (ull)b.mask,
					 (ull)am[i], (ull)bm[j], (ull)r,
					 (ull)ra.value, (ull)ra.mask);
				return 1;
			}
		}
	return 0;
}

static u64 c_add(u64 x, u64 y) { return x + y; }
static u64 c_sub(u64 x, u64 y) { return x - y; }
static u64 c_and(u64 x, u64 y) { return x & y; }
static u64 c_or(u64 x, u64 y)  { return x | y; }
static u64 c_xor(u64 x, u64 y) { return x ^ y; }
static u64 c_mul(u64 x, u64 y) { return x * y; }

int fuzz_case(struct fuzz_input *in, char *msg, size_t msglen)
{
	struct tnum a = gen_tnum(in, 6);
	struct tnum b = gen_tnum(in, 6);
	u64 am[1 << 6], bm[1 << 6];
	int an = enumerate(a, am, 1 << 6);
	int bn = enumerate(b, bm, 1 << 6);
	if (an < 0 || bn < 0)
		return 0;

	struct { const char *n; struct tnum (*op)(struct tnum, struct tnum);
		 u64 (*c)(u64, u64); } binops[] = {
		{ "add", tnum_add, c_add },
		{ "sub", tnum_sub, c_sub },
		{ "and", tnum_and, c_and },
		{ "or",  tnum_or,  c_or  },
		{ "xor", tnum_xor, c_xor },
		{ "mul", tnum_mul, c_mul },
	};
	for (unsigned k = 0; k < ARRAY_SIZE(binops); k++) {
		struct tnum r = binops[k].op(a, b);
		if (check_binop(binops[k].n, r, a, b, am, an, bm, bn,
				binops[k].c, msg, msglen))
			return 1;
	}

	/* Unary shifts: check against every member of a. */
	u8 sh = (u8)(fuzz_u64(in) & 63);
	struct tnum rl = tnum_lshift(a, sh), rr = tnum_rshift(a, sh);
	for (int i = 0; i < an; i++) {
		if (!tnum_member(am[i] << sh, rl)) {
			snprintf(msg, msglen, "UNSOUND tnum_lshift sh=%u a={%#llx,%#llx} x=%#llx",
				 sh, (ull)a.value, (ull)a.mask, (ull)am[i]);
			return 1;
		}
		if (!tnum_member(am[i] >> sh, rr)) {
			snprintf(msg, msglen, "UNSOUND tnum_rshift sh=%u a={%#llx,%#llx} x=%#llx",
				 sh, (ull)a.value, (ull)a.mask, (ull)am[i]);
			return 1;
		}
	}
	return 0;
}

const char *fuzz_name = "tnum_soundness";
