    /* aescfb: full AES-128-CFB round trip through the real lib/crypto code --
     * aes_prepareenckey() (key schedule from aes.c) then aescfb_encrypt() and
     * aescfb_decrypt() over one block. Key and plaintext bytes are map-seeded
     * so the key schedule and both feedback paths stay live. BPF_ASSERT pins
     * the roundtrip property: decrypt(encrypt(p)) == p. State lives in a
     * static global area (__bpf_cfb): the expanded key alone is ~272 bytes,
     * past the 512-byte BPF stack with callee frames. */
    __u32 k0 = 0, k1 = 1;
    __u64 *ka = bpf_map_lookup_elem(&input_map, &k0);
    __u64 *pa = bpf_map_lookup_elem(&input_map, &k1);

    int i;
    #pragma clang loop unroll(disable)
    for (i = 0; i < 16; i++) {
        __bpf_cfb.key[i] = (u8)((ka ? *ka : 0x0123456789abcdefULL) >> ((i & 7) * 8));
        __bpf_cfb.pt[i]  = (u8)((pa ? *pa : 0xfedcba9876543210ULL) >> ((i & 7) * 8));
        __bpf_cfb.iv[i]  = (u8)(i * 17);
    }

    struct aes_enckey ek;
    if (aes_prepareenckey(&ek, __bpf_cfb.key, 16))
        return -1;
    /* AES-128 always expands to 10 rounds; the guard makes that a
     * verifier-known fact on the surviving path, bounding aes_encrypt's
     * round-key indexing (unknown nrounds was walking off the key area). */
    if (ek.nrounds != 10)
        return -1;

    aescfb_encrypt(&ek, __bpf_cfb.ct, __bpf_cfb.pt, 16, __bpf_cfb.iv);
    aescfb_decrypt(&ek, __bpf_cfb.out, __bpf_cfb.ct, 16, __bpf_cfb.iv);

    #pragma clang loop unroll(disable)
    for (i = 0; i < 16; i++)
        BPF_ASSERT(__bpf_cfb.out[i] == __bpf_cfb.pt[i]);

    return __bpf_cfb.ct[0];
