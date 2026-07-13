/* bcd: bin->bcd->bin roundtrip over the valid 0..99 domain, folded across 8
 * seeded values. Tiny, but the out-of-line _bin2bcd/_bcd2bin are div/mod-by-10
 * codegen. */
static __u64 diff_compute(const __u64 in[4])
{
	__u64 r = 0;
	int i;

	for (i = 0; i < 8; i++) {
		unsigned v = (unsigned)((in[i & 3] >> (i * 7)) % 100);
		unsigned char b = _bin2bcd(v);

		r = (r << 8) ^ b ^ ((__u64)_bcd2bin(b) << 32);
	}
	return r;
}
