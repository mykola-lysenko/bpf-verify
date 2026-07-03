// SPDX-License-Identifier: GPL-2.0-only
/*
 * ASAN/UBSan fuzzer for mldsa_verify() (lib/crypto/mldsa.c) -- ML-DSA / Dilithium
 * post-quantum signature verification, one of the newest and least-fuzzed
 * pieces of kernel crypto.
 *
 * mldsa_verify() parses an attacker-controlled signature and public key
 * (unpacking polynomials, decoding hints, running SHAKE) before deciding
 * validity. That parsing of untrusted, structured data is exactly where a
 * fresh implementation might read out of bounds. We call it with the CORRECT
 * length for the chosen parameter set but fully fuzzed contents, so verification
 * proceeds into the unpack/decode paths instead of bouncing off the length
 * check. Signature and public key live in heap buffers with tight ASan
 * redzones; any over-read traps. mldsa.c + sha3.c (generic Keccak) are linked
 * via mldsa.sources.
 */
#include "fuzz.h"
#include <stdlib.h>
#include <crypto/mldsa.h>

struct pset { enum mldsa_alg alg; size_t sig, pk; };
static const struct pset psets[] = {
	{ MLDSA44, MLDSA44_SIGNATURE_SIZE, MLDSA44_PUBLIC_KEY_SIZE },
	{ MLDSA65, MLDSA65_SIGNATURE_SIZE, MLDSA65_PUBLIC_KEY_SIZE },
	{ MLDSA87, MLDSA87_SIGNATURE_SIZE, MLDSA87_PUBLIC_KEY_SIZE },
};

int fuzz_case(struct fuzz_input *in, char *msg_unused, size_t msglen)
{
	(void)msg_unused; (void)msglen;
	const struct pset *p = &psets[fuzz_u64(in) % 3];

	/* Occasionally perturb the length to also exercise the size checks;
	 * mostly use the exact length so parsing proceeds. */
	size_t sig_len = p->sig, pk_len = p->pk;
	if ((fuzz_u64(in) & 7) == 0)
		sig_len = (size_t)fuzz_range(in, 0, p->sig + 8);
	if ((fuzz_u64(in) & 7) == 0)
		pk_len = (size_t)fuzz_range(in, 0, p->pk + 8);

	unsigned char *sig = malloc(sig_len ? sig_len : 1);
	unsigned char *pk = malloc(pk_len ? pk_len : 1);
	unsigned char mbuf[32];
	size_t mlen = (size_t)fuzz_range(in, 0, sizeof(mbuf));
	if (!sig || !pk) {
		free(sig); free(pk);
		return 0;
	}
	fuzz_bytes(in, sig, sig_len);
	fuzz_bytes(in, pk, pk_len);
	fuzz_bytes(in, mbuf, mlen);

	/* Return value irrelevant (malformed input -> -EBADMSG/-EKEYREJECTED is
	 * correct); ASan enforces the memory-safety contract. */
	volatile int r = mldsa_verify(p->alg, sig, sig_len, mbuf, mlen, pk, pk_len);
	(void)r;

	free(sig);
	free(pk);
	return 0;
}

const char *fuzz_name = "mldsa";
