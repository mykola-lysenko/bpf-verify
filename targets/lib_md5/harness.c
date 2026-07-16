    /* MD5 compression over one 64-byte block. Property: determinism. */
    __u32 k0 = 0;
    struct __bpf_md5_data *d = bpf_map_lookup_elem(&__bpf_md5_map, &k0);
    if (!d) return 0;
    __u32 s0 = 0, s1 = 1;
    __u64 *a = bpf_map_lookup_elem(&input_map, &s0);
    __u64 *b = bpf_map_lookup_elem(&input_map, &s1);
    int i;
    #pragma clang loop unroll(disable)
    for (i = 0; i < MD5_BLOCK_SIZE; i++)
        d->block[i] = (u8)(((a ? *a : 0x0123456789abcdefULL) ^
                            (b ? *b : 0xfedcba98ULL) * (i + 1)) >> ((i & 7) * 8));
    /* MD5 IV (a,b,c,d) */
    static const u32 iv[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
    #pragma clang loop unroll(disable)
    for (i = 0; i < 4; i++) { d->st1.h[i] = iv[i]; d->st2.h[i] = iv[i]; }
    md5_block(&d->st1, d->block);
    md5_block(&d->st2, d->block);
    #pragma clang loop unroll(disable)
    for (i = 0; i < 4; i++)
        BPF_ASSERT(d->st1.h[i] == d->st2.h[i]);
    return 0;
