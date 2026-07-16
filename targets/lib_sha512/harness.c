    /* SHA-512 compression over one 128-byte block. Seed the block from the map
     * so the round function stays live; run it through sha512_init +
     * sha512_blocks_generic and read back a state word. Property: determinism --
     * the same block into two fresh states yields identical state (a
     * codegen/carry bug in the 64-bit round function would break it).
     * execute:true fuzzes this per iteration (0 = pass). */
    __u32 k0 = 0;
    struct __bpf_sha512_data *d = bpf_map_lookup_elem(&__bpf_sha512_map, &k0);
    if (!d) return 0;

    __u32 s0 = 0, s1 = 1;
    __u64 *a = bpf_map_lookup_elem(&input_map, &s0);
    __u64 *b = bpf_map_lookup_elem(&input_map, &s1);
    int i;
    #pragma clang loop unroll(disable)
    for (i = 0; i < SHA512_BLOCK_SIZE; i++)
        d->block[i] = (u8)(((a ? *a : 0x0123456789abcdefULL) ^
                            (b ? *b : 0xfedcba98ULL) * (i + 1)) >> ((i & 7) * 8));

    sha512_init(&d->ctx);
    sha512_blocks_generic(&d->ctx.ctx.state, d->block, 1);
    u64 h0 = d->ctx.ctx.state.h[0];
    u64 h7 = d->ctx.ctx.state.h[7];

    /* determinism: a second fresh state over the same block must match */
    sha512_init(&d->ctx2);
    sha512_blocks_generic(&d->ctx2.ctx.state, d->block, 1);
    BPF_ASSERT(d->ctx2.ctx.state.h[0] == h0);
    BPF_ASSERT(d->ctx2.ctx.state.h[7] == h7);

    return 0;
