    /* BLAKE2b compression over one 128-byte block. Property: determinism --
     * the same seeded chaining state + block compressed twice must match. */
    __u32 k0 = 0;
    struct __bpf_b2b_data *d = bpf_map_lookup_elem(&__bpf_b2b_map, &k0);
    if (!d) return 0;
    __u32 s0 = 0, s1 = 1;
    __u64 *a = bpf_map_lookup_elem(&input_map, &s0);
    __u64 *b = bpf_map_lookup_elem(&input_map, &s1);
    int i;
    #pragma clang loop unroll(disable)
    for (i = 0; i < BLAKE2B_BLOCK_SIZE; i++)
        d->block[i] = (u8)(((a ? *a : 0x0123456789abcdefULL) ^
                            (b ? *b : 0xfeedfaceULL) * (i + 1)) >> ((i & 7) * 8));
    /* seed chaining values h[0..7] identically in both ctxs; t/f = 0 */
    #pragma clang loop unroll(disable)
    for (i = 0; i < 8; i++) {
        u64 hv = (a ? *a : 0x6a09e667f3bcc908ULL) + (u64)i * 0x9e3779b97f4a7c15ULL;
        d->c1.h[i] = hv; d->c2.h[i] = hv;
    }
    #pragma clang loop unroll(disable)
    for (i = 0; i < 2; i++) { d->c1.t[i]=0; d->c2.t[i]=0; d->c1.f[i]=0; d->c2.f[i]=0; }

    blake2b_compress_generic(&d->c1, d->block, 1, BLAKE2B_BLOCK_SIZE);
    blake2b_compress_generic(&d->c2, d->block, 1, BLAKE2B_BLOCK_SIZE);
    #pragma clang loop unroll(disable)
    for (i = 0; i < 8; i++)
        BPF_ASSERT(d->c1.h[i] == d->c2.h[i]);
    return 0;
