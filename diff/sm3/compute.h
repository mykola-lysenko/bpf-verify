/* sm3: SM3 compression over one 64-byte block, native vs BPF -- 64 rounds of
 * 32-bit add/rotate/FF/GG with message expansion (W[68]/W'[64] via W[16]).
 * State + block in a static .bss area. */
static struct { struct sm3_block_state st; u8 block[SM3_BLOCK_SIZE]; u32 W[16]; } __d;
static __u64 diff_compute(const __u64 in[4])
{
	static const u32 iv[8] = { 0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,
				   0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e };
	int i;
	for (i = 0; i < SM3_BLOCK_SIZE; i++)
		__d.block[i] = (u8)((in[i & 3] ^ (in[(i + 1) & 3] * (i + 1))) >> ((i & 7) * 8));
	for (i = 0; i < 8; i++) __d.st.h[i] = iv[i];
	sm3_block_generic(&__d.st, __d.block, __d.W);
	{ __u64 acc = 0; for (i = 0; i < 8; i++) acc ^= (__u64)__d.st.h[i] << ((i & 1) * 32); return acc; }
}
