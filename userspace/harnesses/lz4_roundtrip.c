// SPDX-License-Identifier: GPL-2.0-only
/*
 * LZ4 round-trip correctness + mutated-frame safety fuzzer (ASAN/UBSan).
 *
 * Random bytes bounce off the decompressor's early length checks, so this
 * harness first produces a *valid* LZ4 frame with the real kernel compressor,
 * then exercises two properties:
 *
 *   1. Correctness: LZ4_decompress_safe(compress(x)) reproduces x exactly.
 *   2. Safety under corruption: mutating a few bytes of a valid frame must
 *      never make the decompressor read/write out of bounds (ASAN catches it).
 *
 * Feeding the decompressor structurally-valid-then-corrupted input drives it
 * deep into the literal-copy, match-copy, and wildcopy paths where any
 * out-of-bounds bug would live.
 */
#include "fuzz.h"
#include <stdlib.h>
#include <string.h>

/* Both translation units share the guarded lz4defs.h, so they coexist in one
 * TU. Paths come from the .flags file. */
#include KLZ4_C_SRC
#include KLZ4_D_SRC

int fuzz_case(struct fuzz_input *in, char *msg, size_t msglen)
{
	int in_size = (int)fuzz_range(in, 0, 400);
	/* Bias plaintext toward low-entropy / repetitive data so the compressor
	 * actually emits matches (not just literals). */
	unsigned char *plain = malloc(in_size ? in_size : 1);
	if (!plain)
		return 0;
	int mode = (int)fuzz_range(in, 0, 3);
	for (int i = 0; i < in_size; i++) {
		switch (mode) {
		case 0: plain[i] = (unsigned char)fuzz_u64(in); break;    /* random */
		case 1: plain[i] = (unsigned char)(fuzz_u64(in) & 0x3); break; /* 4-symbol */
		case 2: plain[i] = (unsigned char)(i & 0xff); break;      /* ramp */
		default: plain[i] = 0xAB; break;                          /* constant */
		}
	}

	int bound = LZ4_compressBound(in_size);
	if (bound <= 0)
		bound = 1;
	char *comp = malloc(bound);
	void *wrk = malloc(LZ4_MEM_COMPRESS);
	if (!comp || !wrk) {
		free(plain); free(comp); free(wrk);
		return 0;
	}
	int clen = LZ4_compress_default((const char *)plain, comp, in_size, bound, wrk);

	int rc = 0;
	if (clen > 0) {
		/* Property 1: clean round-trip reproduces the plaintext exactly. */
		char *out = malloc(in_size ? in_size : 1);
		if (out) {
			int dlen = LZ4_decompress_safe(comp, out, clen, in_size);
			if (dlen != in_size || (in_size && memcmp(out, plain, in_size))) {
				snprintf(msg, msglen,
					 "round-trip mismatch: in=%d clen=%d dlen=%d",
					 in_size, clen, dlen);
				rc = 1;
			}
			free(out);
		}

		/* Property 2: corrupt a few bytes and require memory-safe decode into
		 * a bounded buffer. The return value is ignored (a negative result on
		 * corrupt input is correct); ASAN enforces the safety contract. */
		if (!rc) {
			int nmut = (int)fuzz_range(in, 1, 6);
			for (int m = 0; m < nmut && clen > 0; m++)
				comp[fuzz_u64(in) % clen] ^= (unsigned char)fuzz_u64(in);
			int cap = (int)fuzz_range(in, 0, 512);
			char *out2 = malloc(cap ? cap : 1);
			if (out2) {
				volatile int r = LZ4_decompress_safe(comp, out2, clen, cap);
				(void)r;
				free(out2);
			}
		}
	}

	free(plain); free(comp); free(wrk);
	return rc;
}

const char *fuzz_name = "lz4_roundtrip";
