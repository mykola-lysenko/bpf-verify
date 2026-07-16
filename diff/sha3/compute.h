/* sha3: the Keccak-f[1600] permutation over a seeded 200-byte state, native vs
 * BPF -- 24 rounds of theta/rho/pi/chi/iota, a lattice of 64-bit rotates and
 * xors unlike any other target's codegen. Seed the state, permute, fold the
 * 25 native words. State in a static .bss area (200 bytes + the round-function
 * frame overflow the 512-byte stack otherwise; the permutation reads no
 * loop bound from the state). */
#ifndef __bpf__
/* native: sha3's unexercised absorb XOR pulls __crypto_xor (the BPF side gets
 * it from the lib_sha3 preamble). */
void __crypto_xor(u8 *dst, const u8 *src1, const u8 *src2, unsigned int size)
{ while (size--) *dst++ = *src1++ ^ *src2++; }
#endif
static struct { struct sha3_state st; } __d3;

static __u64 diff_compute(const __u64 in[4])
{
	int i;

	for (i = 0; i < SHA3_STATE_SIZE; i++)
		__d3.st.bytes[i] = (u8)((in[i & 3] ^ (in[(i + 1) & 3] * (i + 1))) >> ((i & 7) * 8));

	sha3_keccakf_generic(&__d3.st);

	{
		__u64 acc = 0;
		for (i = 0; i < SHA3_STATE_SIZE / 8; i++)
			acc ^= __d3.st.native_words[i] * (0x100000001b3ULL + i);
		return acc;
	}
}
