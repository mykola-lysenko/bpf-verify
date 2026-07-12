/* __crypto_xor backs crypto_xor()/crypto_xor_cpy() when the length isn't a
 * compile-time constant (lib/crypto/utils.c); real byte-wise implementation so
 * the GCM counter-mode data path stays genuine. */
void __crypto_xor(u8 *dst, const u8 *src1, const u8 *src2, unsigned int size)
{
	while (size--)
		*dst++ = *src1++ ^ *src2++;
}

/* __crypto_memneq backs crypto_memneq() -- aesgcm_decrypt's constant-time
 * auth-tag comparison (lib/crypto/utils.c). Faithful xor-accumulate. */
unsigned long __crypto_memneq(const void *a, const void *b, size_t size)
{
	const u8 *pa = a, *pb = b;
	unsigned long neq = 0;

	while (size--)
		neq |= (unsigned long)(*pa++ ^ *pb++);
	return neq;
}

/* All state, including the aesgcm_ctx, lives in a static global area: the
 * fully-inlined GCM call graph (AES rounds + GHASH + CTR locals) exceeds the
 * 512-byte stack with the ~280-byte ctx in-frame. Under full inlining clang
 * constant-folds nrounds (keysize is the literal 16), so the aes round-key
 * indexing stays bounded without the verifier needing to read nrounds back
 * from map memory (which is what broke the non-inlined aescfb attempt). */
static struct {
	struct aesgcm_ctx gctx;
	u8 key[16], pt[16], ct[16], out[16], tag[16];
	u8 iv[12], assoc[8];
} __bpf_gcm;
