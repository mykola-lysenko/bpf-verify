    /* SHA-3: run the Keccak-f[1600] permutation on a seeded 200-byte state.
     * Property: determinism -- the same seed permuted into two states must
     * match (a codegen bug in the 64-bit rotate/xor lattice would break it).
     * execute:true fuzzes this per iteration (0 = pass). */
    __u32 k0 = 0;
    struct __bpf_sha3_data *d = bpf_map_lookup_elem(&__bpf_sha3_map, &k0);
    if (!d) return 0;

    __u32 s0 = 0, s1 = 1;
    __u64 *a = bpf_map_lookup_elem(&input_map, &s0);
    __u64 *b = bpf_map_lookup_elem(&input_map, &s1);
    int i;
    #pragma clang loop unroll(disable)
    for (i = 0; i < SHA3_STATE_SIZE; i++)
        d->seed[i] = (u8)(((a ? *a : 0x0123456789abcdefULL) ^
                           (b ? *b : 0xfeedface00c0ffeeULL) * (i + 1)) >> ((i & 7) * 8));

    #pragma clang loop unroll(disable)
    for (i = 0; i < SHA3_STATE_SIZE; i++) { d->st1.bytes[i] = d->seed[i]; d->st2.bytes[i] = d->seed[i]; }

    sha3_keccakf_generic(&d->st1);
    sha3_keccakf_generic(&d->st2);

    #pragma clang loop unroll(disable)
    for (i = 0; i < SHA3_STATE_SIZE / 8; i++)
        BPF_ASSERT(d->st1.native_words[i] == d->st2.native_words[i]);

    return 0;
