/* Externs referenced from other TUs, on the exercised path:
 * __crypto_xor backs crypto_xor_cpy() when the length isn't compile-time
 * constant (lib/crypto/utils.c). Real byte-wise implementation so the CFB data
 * path stays genuine. (memzero_explicit is already static inline in string.h;
 * its extern-looking reference resolves once __crypto_xor stops the cascade.) */
void __crypto_xor(u8 *dst, const u8 *src1, const u8 *src2, unsigned int size)
{
	while (size--)
		*dst++ = *src1++ ^ *src2++;
}

/* The expanded key (~272B) plus I/O buffers exceed the 512-byte BPF stack once
 * callee frames are added; keep them in a static global area (.bss-backed map)
 * instead. */
/* Only the byte buffers live here; the expanded key stays on the harness
 * STACK. That placement matters for verification, not just space: aes_encrypt
 * indexes rndkeys by ek.nrounds, and the verifier tracks stack-stored values
 * precisely (nrounds == 10 -> bounded indexing), whereas anything loaded from
 * map-backed memory is an unknown scalar whose exploration walks off the end
 * of the area regardless of padding. */
static struct {
	u8 key[16], pt[16], iv[16], ct[16], out[16];
} __bpf_cfb;
