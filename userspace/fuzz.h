// SPDX-License-Identifier: GPL-2.0-only
/*
 * fuzz.h — tiny property-fuzzing framework for userspace kernel-code harnesses.
 *
 * A harness includes this, then defines:
 *   int fuzz_case(struct fuzz_input *in, char *msg, size_t msglen);
 *   const char *fuzz_name;
 * fuzz_case pulls inputs via fuzz_u64()/fuzz_bytes() and returns 0 on success
 * or non-zero on a property violation (writing a human message into msg).
 * The driver (fuzz_main.c) provides main(): a reproducible per-iteration seed,
 * corner-value biasing, and repro reporting.
 */
#ifndef FUZZ_H
#define FUZZ_H

#include "khost.h"
#include <stdio.h>

struct fuzz_input {
	uint64_t state;   /* splitmix64 state, reseeded per iteration */
	long draw;        /* how many values drawn so far this iteration */
	long iter;        /* current iteration index */
};

static inline uint64_t fuzz__next(struct fuzz_input *in)
{
	uint64_t z = (in->state += 0x9e3779b97f4a7c15ULL);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return z ^ (z >> 31);
}

/* Corner values worth hitting deterministically before random ones. */
static const uint64_t fuzz__corners[] = {
	0, 1, 2, 3, ~0ULL, ~0ULL - 1,
	0x8000000000000000ULL, 0x7fffffffffffffffULL,
	0xffffffffULL, 0x100000000ULL, 0x80000000ULL, 0x7fffffffULL,
	0xffULL, 0x100ULL, 0xffffULL, 0x10000ULL,
};
#define FUZZ_NCORNERS (sizeof(fuzz__corners) / sizeof(fuzz__corners[0]))

/* Draw a u64. The first few iterations sweep corner values across the first
 * two draws; afterwards everything is pseudo-random. */
static inline uint64_t fuzz_u64(struct fuzz_input *in)
{
	long d = in->draw++;
	if (in->iter < (long)(FUZZ_NCORNERS * FUZZ_NCORNERS)) {
		if (d == 0)
			return fuzz__corners[in->iter % FUZZ_NCORNERS];
		if (d == 1)
			return fuzz__corners[(in->iter / FUZZ_NCORNERS) % FUZZ_NCORNERS];
	}
	return fuzz__next(in);
}

/* Fill buf with fuzzed bytes. */
static inline void fuzz_bytes(struct fuzz_input *in, void *buf, size_t n)
{
	unsigned char *p = buf;
	for (size_t i = 0; i < n; i++)
		p[i] = (unsigned char)fuzz_u64(in);
}

/* Draw a value in [lo, hi]. */
static inline uint64_t fuzz_range(struct fuzz_input *in, uint64_t lo, uint64_t hi)
{
	if (hi <= lo)
		return lo;
	return lo + fuzz_u64(in) % (hi - lo + 1);
}

int fuzz_case(struct fuzz_input *in, char *msg, size_t msglen);
extern const char *fuzz_name;
extern unsigned long khost_warn_count;

#endif /* FUZZ_H */
