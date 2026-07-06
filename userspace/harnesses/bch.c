// SPDX-License-Identifier: GPL-2.0-only
/*
 * Property + ASan fuzzer for the BCH error-correcting code (lib/bch.c).
 *
 * Unlike a boot decompressor, error correction is *designed* to handle corrupt
 * input (that is its purpose), so both a correctness property and memory safety
 * on arbitrary input are squarely in scope:
 *
 *   1. Correctness: for up to t random bit-flips in a codeword, bch_decode()
 *      must report the errors and locate them so that applying the corrections
 *      recovers the original data exactly.
 *   2. Safety: fed an arbitrary (possibly uncorrectable) received codeword,
 *      bch_decode() must not read or write out of bounds (ASan).
 *
 * bch_init() builds the Galois-field tables once and is reused across
 * iterations. bch.c + bitrev.c are linked via bch.sources.
 */
#include "fuzz.h"
#include <stdlib.h>
#include <string.h>
#include <linux/bch.h>

#define BCH_M 13
#define BCH_T 4
#define DATA_LEN 32   /* bytes of data protected per codeword */

static struct bch_control *bch;
static unsigned int ecc_bytes;

static void flip_bit(uint8_t *buf, unsigned int bit)
{
	buf[bit / 8] ^= (uint8_t)(1u << (bit % 8));
}

int fuzz_case(struct fuzz_input *in, char *msg, size_t msglen)
{
	if (!bch) {
		bch = bch_init(BCH_M, BCH_T, 0, false);
		if (!bch)
			return 0;
		ecc_bytes = bch->ecc_bytes;
	}

	uint8_t data[DATA_LEN], recv[DATA_LEN];
	uint8_t ecc[32] = {0}, recv_ecc[32];
	unsigned int errloc[BCH_T];
	/* Inject errors only in the fully-used data bytes: the ecc's last byte
	 * has (ecc_bytes*8 - ecc_bits) padding bits that are not part of the
	 * codeword, so flipping them would create phantom, uncountable errors. */
	unsigned int data_bits = DATA_LEN * 8;

	for (unsigned i = 0; i < DATA_LEN; i++)
		data[i] = (uint8_t)fuzz_u64(in);
	bch_encode(bch, data, DATA_LEN, ecc);

	if ((fuzz_u64(in) & 3) != 0) {
		/* Correctness arm: inject <= t flips at known positions. */
		memcpy(recv, data, DATA_LEN);
		memcpy(recv_ecc, ecc, ecc_bytes);
		unsigned int nflip = (unsigned)fuzz_range(in, 0, BCH_T);
		unsigned int pos[BCH_T];
		unsigned int used = 0;
		for (unsigned i = 0; i < nflip; i++) {
			unsigned int b = (unsigned)fuzz_range(in, 0, data_bits - 1);
			/* avoid flipping the same bit twice (would cancel) */
			int dup = 0;
			for (unsigned j = 0; j < used; j++)
				if (pos[j] == b) dup = 1;
			if (dup) continue;
			pos[used++] = b;
			flip_bit(recv, b);
		}
		int nerr = bch_decode(bch, recv, DATA_LEN, recv_ecc, NULL, NULL, errloc);
		if (nerr < 0) {
			snprintf(msg, msglen, "decode failed (%d) for %u correctable flips",
				 nerr, used);
			return 1;
		}
		if ((unsigned)nerr != used) {
			snprintf(msg, msglen, "decode found %d errors, injected %u", nerr, used);
			return 1;
		}
		/* Apply corrections and verify the data is recovered. */
		for (int i = 0; i < nerr; i++) {
			unsigned int b = errloc[i];
			if (b < data_bits)
				flip_bit(recv, b);
			else if (b < data_bits + ecc_bytes * 8)
				flip_bit(recv_ecc, b - data_bits);
		}
		if (memcmp(recv, data, DATA_LEN) != 0) {
			snprintf(msg, msglen, "corrected data != original (%u flips)", used);
			return 1;
		}
	} else {
		/* Safety arm: arbitrary received codeword; only ASan matters. */
		for (unsigned i = 0; i < DATA_LEN; i++)
			recv[i] = (uint8_t)fuzz_u64(in);
		for (unsigned i = 0; i < ecc_bytes; i++)
			recv_ecc[i] = (uint8_t)fuzz_u64(in);
		volatile int nerr = bch_decode(bch, recv, DATA_LEN, recv_ecc,
					       NULL, NULL, errloc);
		(void)nerr;
	}
	return 0;
}

const char *fuzz_name = "bch";
