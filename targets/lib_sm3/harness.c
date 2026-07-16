    /* SM3 compression over one 64-byte block. Property: determinism -- the same
     * block into two fresh states must match. execute:true fuzzes it (0 = pass). */
    __u32 k0 = 0;
    struct __bpf_sm3_data *d = bpf_map_lookup_elem(&__bpf_sm3_map, &k0);
    if (!d) return 0;
    __u32 s0 = 0, s1 = 1;
    __u64 *a = bpf_map_lookup_elem(&input_map, &s0);
    __u64 *b = bpf_map_lookup_elem(&input_map, &s1);
    int i;
    #pragma clang loop unroll(disable)
    for (i = 0; i < SM3_BLOCK_SIZE; i++)
        d->block[i] = (u8)(((a ? *a : 0x0123456789abcdefULL) ^
                            (b ? *b : 0xfedcba98ULL) * (i + 1)) >> ((i & 7) * 8));
    /* SM3 IV */
    static const u32 iv[8] = { 0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,
                               0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e };
    #pragma clang loop unroll(disable)
    for (i = 0; i < 8; i++) { d->st1.h[i] = iv[i]; d->st2.h[i] = iv[i]; }
    sm3_block_generic(&d->st1, d->block, d->W);
    sm3_block_generic(&d->st2, d->block, d->W);
    #pragma clang loop unroll(disable)
    for (i = 0; i < 8; i++)
        BPF_ASSERT(d->st1.h[i] == d->st2.h[i]);
    return 0;
