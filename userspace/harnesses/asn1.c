// SPDX-License-Identifier: GPL-2.0-only
/*
 * ASAN/UBSan fuzzer for asn1_ber_decoder() (lib/asn1_decoder.c) on malformed
 * BER/DER. The decoder walks tag/length/value structure from an
 * attacker-controlled buffer -- the TLV length parsing here is grammar-
 * independent and has real out-of-bounds CVE history (CVE-2016-2053). We drive
 * it with the generated rsapubkey grammar and fully fuzzed input; the actions
 * are no-ops. Data lives in a tight-redzone heap buffer; any over-read traps.
 */
#include "fuzz.h"
#include <stdlib.h>
#include "rsapubkey.asn1.h"   /* generated: rsapubkey_decoder + action protos */

/* No-op action callbacks referenced by the generated decoder. */
int rsa_get_n(void *ctx, size_t hdrlen, unsigned char tag,
	      const void *value, size_t vlen)
{ (void)ctx; (void)hdrlen; (void)tag; (void)value; (void)vlen; return 0; }
int rsa_get_e(void *ctx, size_t hdrlen, unsigned char tag,
	      const void *value, size_t vlen)
{ (void)ctx; (void)hdrlen; (void)tag; (void)value; (void)vlen; return 0; }

int fuzz_case(struct fuzz_input *in, char *msg, size_t msglen)
{
	(void)msg; (void)msglen;
	size_t len = (size_t)fuzz_range(in, 0, 300);
	unsigned char *data = malloc(len ? len : 1);
	if (!data)
		return 0;
	fuzz_bytes(in, data, len);
	volatile int r = asn1_ber_decoder(&rsapubkey_decoder, NULL, data, len);
	(void)r;
	free(data);
	return 0;
}

const char *fuzz_name = "asn1";
