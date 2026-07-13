/* aescfb: AES-128-CFB single-block encrypt, native vs BPF. Exercises the AES
 * key schedule, S-box table indexing, and the CFB feedback/xor path -- dense
 * shift/xor/table codegen where a BPF-backend miscompile would surface.
 *
 * Both sides run this exact function; the BPF side gets aes.c from the
 * targets/aescfb pre_include, the native side pulls it via DIFF_AES_C
 * (set in native.flags). */
#ifndef __bpf__
/* native: aes.c uses barrier() (normally from the kernel compiler headers,
 * blocked on the host); an empty asm clobber is the faithful equivalent. */
#ifndef barrier
#define barrier() __asm__ __volatile__("" ::: "memory")
#endif
#endif
#ifdef DIFF_AES_C
#include DIFF_AES_C
#endif
#ifndef __bpf__
/* native: __crypto_xor is extern in crypto/utils.h and lib/crypto/utils.c is
 * not linked; provide the byte-wise reference (BPF side has it in the target
 * preamble). */
void __crypto_xor(u8 *dst, const u8 *src1, const u8 *src2, unsigned int size)
{
	while (size--)
		*dst++ = *src1++ ^ *src2++;
}
#endif

/* Static area rather than diff_compute()'s frame: on the BPF side the fully
 * inlined AES call graph plus a stack key schedule already presses the 512-byte
 * limit; only the expanded key must stay on the stack (verifier-known nrounds,
 * see targets/aescfb/preamble.h). */
static struct {
	u8 key[16], pt[16], iv[16], ct[16];
} __diff_cfb;

static __u64 diff_compute(const __u64 in[4])
{
	int i;

	for (i = 0; i < 8; i++) {
		__diff_cfb.key[i]     = (u8)(in[0] >> (i * 8));
		__diff_cfb.key[i + 8] = (u8)(in[1] >> (i * 8));
		__diff_cfb.pt[i]      = (u8)(in[2] >> (i * 8));
		__diff_cfb.pt[i + 8]  = (u8)(in[3] >> (i * 8));
		__diff_cfb.iv[i]      = (u8)(i * 17 + 3);
		__diff_cfb.iv[i + 8]  = (u8)(i * 29 + 7);
	}

	{
		struct aes_enckey ek;

		if (aes_prepareenckey(&ek, __diff_cfb.key, 16))
			return 0xdeadULL;
		aescfb_encrypt(&ek, __diff_cfb.ct, __diff_cfb.pt, 16,
			       __diff_cfb.iv);
	}

	{
		__u64 lo = 0, hi = 0;

		for (i = 0; i < 8; i++) {
			lo |= (__u64)__diff_cfb.ct[i] << (i * 8);
			hi |= (__u64)__diff_cfb.ct[i + 8] << (i * 8);
		}
		return lo ^ hi;
	}
}
