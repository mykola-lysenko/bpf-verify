/* aesgcm: AES-128-GCM single-block encrypt + auth tag, native vs BPF.
 * Exercises the AES key schedule, CTR keystream, GF(2^128) GHASH multiply and
 * the tag path -- wide-integer/carry-heavy codegen on the BPF side (32-bit
 * clmul route, no INT128) vs the host's native path, so representation bugs
 * in either backend surface as a diff.
 *
 * BPF side: aes.c + gf128hash.c arrive via targets/aesgcm/pre_include (with
 * the harness-contract pins documented there). Native side: pulled in here
 * via DIFF_AES_C / DIFF_GF128_C; the real (unpinned) kernel paths run, so a
 * pin that changed semantics would show up as a divergence. */
#ifndef __bpf__
#ifndef barrier
#define barrier() __asm__ __volatile__("" ::: "memory")
#endif
#endif
#ifdef DIFF_AES_C
#include DIFF_AES_C
#endif
#ifdef DIFF_GF128_C
#include DIFF_GF128_C
#endif
#ifndef __bpf__
/* native: extern helpers from lib/crypto/utils.c (not linked); byte-wise
 * references (BPF side gets these from targets/aesgcm/preamble.h). */
void __crypto_xor(u8 *dst, const u8 *src1, const u8 *src2, unsigned int size)
{
	while (size--)
		*dst++ = *src1++ ^ *src2++;
}
unsigned long __crypto_memneq(const void *a, const void *b, size_t size)
{
	const u8 *pa = a, *pb = b;
	unsigned long neq = 0;

	while (size--)
		neq |= (unsigned long)(*pa++ ^ *pb++);
	return neq;
}
#endif

static struct {
	struct aesgcm_ctx gctx;
	u8 key[16], pt[16], ct[16], tag[16];
	u8 iv[12], assoc[8];
} __diff_gcm;

static __u64 diff_compute(const __u64 in[4])
{
	int i;

	for (i = 0; i < 8; i++) {
		__diff_gcm.key[i]     = (u8)(in[0] >> (i * 8));
		__diff_gcm.key[i + 8] = (u8)(in[1] >> (i * 8));
		__diff_gcm.pt[i]      = (u8)(in[2] >> (i * 8));
		__diff_gcm.pt[i + 8]  = (u8)(in[3] >> (i * 8));
		__diff_gcm.assoc[i]   = (u8)(in[0] >> (i * 4));
	}
	for (i = 0; i < 12; i++)
		__diff_gcm.iv[i] = (u8)(i * 5 + 1);

	if (aesgcm_expandkey(&__diff_gcm.gctx, __diff_gcm.key, 16, 16))
		return 0xdeadULL;
	aesgcm_encrypt(&__diff_gcm.gctx, __diff_gcm.ct, __diff_gcm.pt, 16,
		       __diff_gcm.assoc, 8, __diff_gcm.iv, __diff_gcm.tag);

	{
		__u64 c = 0, t = 0;

		for (i = 0; i < 8; i++) {
			c |= (__u64)(__diff_gcm.ct[i] ^ __diff_gcm.ct[i + 8]) << (i * 8);
			t |= (__u64)(__diff_gcm.tag[i] ^ __diff_gcm.tag[i + 8]) << (i * 8);
		}
		return c ^ (t << 1) ^ (t >> 63);
	}
}
