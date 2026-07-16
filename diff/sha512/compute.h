/* sha512: the 64-bit SHA-512 compression function over one 128-byte block,
 * native vs BPF -- 80 rounds of 64-bit add / rotate / shift / Ch / Maj, the
 * heaviest 64-bit-arithmetic codegen in the suite. Seed the block, run
 * sha512_init + sha512_blocks_generic, fold the eight 64-bit state words. */
/* ctx + block in a static area (map-backed .bss on BPF): the ~340-byte
 * combined stack of the two-frame call chain overflows the 512-byte limit
 * otherwise. sha512 reads no loop bound from this state (nblocks=1 literal,
 * fixed 80-round loop), so static placement is safe. */
static struct { struct sha512_ctx ctx; u8 block[SHA512_BLOCK_SIZE]; } __d;

static __u64 diff_compute(const __u64 in[4])
{
	int i;

	for (i = 0; i < SHA512_BLOCK_SIZE; i++)
		__d.block[i] = (u8)((in[i & 3] ^ (in[(i + 1) & 3] * (i + 1))) >> ((i & 7) * 8));

	sha512_init(&__d.ctx);
	sha512_blocks_generic(&__d.ctx.ctx.state, __d.block, 1);

	{
		__u64 acc = 0;
		for (i = 0; i < 8; i++)
			acc ^= __d.ctx.ctx.state.h[i] * (0x100000001b3ULL + i);
		return acc;
	}
}
