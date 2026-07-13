    /* aesgcm: full AES-128-GCM roundtrip through the real lib/crypto code --
     * aesgcm_expandkey (AES key schedule + GHASH key derivation), then
     * aesgcm_encrypt (CTR encrypt + GHASH over assoc/ciphertext -> auth tag)
     * and aesgcm_decrypt (tag verify + decrypt). Key/plaintext are map-seeded;
     * BPF_ASSERT pins both properties: the tag authenticates (decrypt returns
     * true) and decrypt(encrypt(p)) == p.
     *
     * execute:true -- Phase 3 fuzz-runs this via BPF_PROG_TEST_RUN with fresh
     * random map seeds per iteration, under the strict return contract:
     * 0 = pass, non-zero = property failure (the BPF_ASSERTs / early -1s). */
    __u32 k0 = 0, k1 = 1;
    __u64 *ka = bpf_map_lookup_elem(&input_map, &k0);
    __u64 *pa = bpf_map_lookup_elem(&input_map, &k1);

    int i;
    #pragma clang loop unroll(disable)
    for (i = 0; i < 16; i++) {
        __bpf_gcm.key[i] = (u8)((ka ? *ka : 0x0123456789abcdefULL) >> ((i & 7) * 8));
        __bpf_gcm.pt[i]  = (u8)((pa ? *pa : 0xfedcba9876543210ULL) >> ((i & 7) * 8));
    }
    #pragma clang loop unroll(disable)
    for (i = 0; i < 12; i++)
        __bpf_gcm.iv[i] = (u8)(i * 5 + 1);
    #pragma clang loop unroll(disable)
    for (i = 0; i < 8; i++)
        __bpf_gcm.assoc[i] = (u8)(0xa0 + i);

    if (aesgcm_expandkey(&__bpf_gcm.gctx, __bpf_gcm.key, 16, 16))
        return -1;

    aesgcm_encrypt(&__bpf_gcm.gctx, __bpf_gcm.ct, __bpf_gcm.pt, 16,
                   __bpf_gcm.assoc, 8, __bpf_gcm.iv, __bpf_gcm.tag);
    bool ok = aesgcm_decrypt(&__bpf_gcm.gctx, __bpf_gcm.out, __bpf_gcm.ct, 16,
                             __bpf_gcm.assoc, 8, __bpf_gcm.iv, __bpf_gcm.tag);
    BPF_ASSERT(ok);

    #pragma clang loop unroll(disable)
    for (i = 0; i < 16; i++)
        BPF_ASSERT(__bpf_gcm.out[i] == __bpf_gcm.pt[i]);

    return 0;
