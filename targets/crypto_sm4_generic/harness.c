    /* crypto/sm4_generic.c: exercise SM4 setkey/encrypt/decrypt wrapper paths. */
    struct crypto_tfm tfm = {};
    u8 key[SM4_KEY_SIZE];
    u8 plain[SM4_BLOCK_SIZE];
    u8 enc[SM4_BLOCK_SIZE];
    u8 dec[SM4_BLOCK_SIZE];
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0x0011223344556677ULL;
    int errors = 0;
    int i;

    for (i = 0; i < SM4_KEY_SIZE; i++) {
        key[i] = (u8)(seed >> ((i & 7) * 8)) ^ (u8)(0x11 * i);
        plain[i] = (u8)(seed >> ((i & 7) * 8)) ^ (u8)(0x5a + i);
    }

    errors |= sm4_setkey(&tfm, key, sizeof(key));
    sm4_encrypt(&tfm, enc, plain);
    sm4_decrypt(&tfm, dec, enc);
    for (i = 0; i < SM4_BLOCK_SIZE; i++)
        errors |= dec[i] != plain[i];

    return errors + dec[0];