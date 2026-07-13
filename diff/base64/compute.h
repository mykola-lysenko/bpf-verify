/* base64: encode 12 seeded bytes (std variant, padded), decode the result,
 * and fold lengths + decoded bytes. Exercises 6-bit repacking shifts both
 * directions; encode of arbitrary bytes is always valid input for decode. */
/* Buffers live in a static global area (map-backed on BPF): the encoder's
 * output cursor advances data-dependently, and on the stack the verifier
 * rejects the write ("invalid write to stack"); in the padded global area the
 * explored range stays in bounds. */
static struct { __u8 src[12], back[16]; char enc[24]; __u8 pad[64]; } __diff_b64;

static __u64 diff_compute(const __u64 in[4])
{
	__u8 *src = __diff_b64.src, *back = __diff_b64.back;
	char *enc = __diff_b64.enc;
	int i, elen, dlen;
	__u64 r;

	for (i = 0; i < 6; i++) {
		src[i]     = (__u8)(in[0] >> (i * 8));
		src[i + 6] = (__u8)(in[1] >> (i * 8));
	}
	elen = base64_encode(src, sizeof(__diff_b64.src), enc, true, BASE64_STD);
	if (elen < 0)
		return 0xdead1ULL;
	/* 12 padded std-variant input bytes always encode to 16 chars. The check
	 * is a live register bound, so the verifier carries it into decode's
	 * loop (unlike memory-reloaded bounds, which reload as unknown). */
	if (elen != 16)
		return 0xdead3ULL;
	dlen = base64_decode(enc, elen, back, true, BASE64_STD);
	if (dlen < 0)
		return 0xdead2ULL;

	r = ((__u64)elen << 40) | ((__u64)dlen << 32);
	for (i = 0; i < dlen && i < 12; i++)
		r ^= (__u64)back[i] << ((i & 7) * 8);
	return r;
}
