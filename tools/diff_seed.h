/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * diff_seed.h — deterministic input generator shared by the native reference
 * driver and the in-UML bpf_runner for native-vs-BPF differential testing.
 *
 * Both sides MUST derive inputs identically from (base_seed, iteration) so a
 * divergence in output is attributable to the compiled code, not to different
 * inputs. Keep this header self-contained (only <stdint.h>).
 */
#ifndef DIFF_SEED_H
#define DIFF_SEED_H

#include <stdint.h>

#define DIFF_NINPUTS 4

/* Boundary values swept across the first inputs before random ones -- these
 * catch off-by-one / overflow codegen bugs that uniform random misses. */
static const uint64_t diff_corners[] = {
	0, 1, 2, 3, ~0ULL, ~0ULL - 1,
	0x8000000000000000ULL, 0x7fffffffffffffffULL,
	0xffffffffULL, 0x100000000ULL, 0x80000000ULL, 0x7fffffffULL,
	0xffULL, 0x100ULL, 0xffffULL, 0x10000ULL,
};
#define DIFF_NCORNERS (sizeof(diff_corners) / sizeof(diff_corners[0]))

static inline uint64_t diff_mix(uint64_t z)
{
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return z ^ (z >> 31);
}

/* Fill out[DIFF_NINPUTS] for a given base seed and iteration index. The first
 * DIFF_NCORNERS^2 iterations sweep corner values across inputs 0 and 1. */
static inline void diff_gen_inputs(uint64_t base, long iter, uint64_t out[DIFF_NINPUTS])
{
	if (iter < (long)(DIFF_NCORNERS * DIFF_NCORNERS)) {
		out[0] = diff_corners[iter % DIFF_NCORNERS];
		out[1] = diff_corners[(iter / DIFF_NCORNERS) % DIFF_NCORNERS];
		for (int k = 2; k < DIFF_NINPUTS; k++)
			out[k] = diff_mix(base + 0x9e3779b97f4a7c15ULL *
					  (uint64_t)(iter * DIFF_NINPUTS + k + 1));
		return;
	}
	for (int k = 0; k < DIFF_NINPUTS; k++)
		out[k] = diff_mix(base + 0x9e3779b97f4a7c15ULL *
				  (uint64_t)(iter * DIFF_NINPUTS + k + 1));
}

#endif /* DIFF_SEED_H */
