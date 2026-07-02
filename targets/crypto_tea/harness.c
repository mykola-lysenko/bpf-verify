    /* crypto/tea.c: exercise TEA, XTEA, and XETA setkey/encrypt/decrypt paths. */
    struct crypto_tfm tfm = {};
    u8 key[TEA_KEY_SIZE];
    u8 plain[TEA_BLOCK_SIZE];
    u8 enc[TEA_BLOCK_SIZE];
    u8 dec[TEA_BLOCK_SIZE];
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0x123456789abcdef0ULL;
    int errors = 0;
    int i;

    for (i = 0; i < TEA_KEY_SIZE; i++)
        key[i] = (u8)(seed >> ((i & 7) * 8)) ^ (u8)(0x33 + i);
    for (i = 0; i < TEA_BLOCK_SIZE; i++)
        plain[i] = (u8)(seed >> ((i & 7) * 8)) ^ (u8)(0xa5 + i);

    tea_setkey(&tfm, key, sizeof(key));
    tea_encrypt(&tfm, enc, plain);
    tea_decrypt(&tfm, dec, enc);
    for (i = 0; i < TEA_BLOCK_SIZE; i++)
        errors |= dec[i] != plain[i];

    xtea_setkey(&tfm, key, sizeof(key));
    xtea_encrypt(&tfm, enc, plain);
    xtea_decrypt(&tfm, dec, enc);
    for (i = 0; i < XTEA_BLOCK_SIZE; i++)
        errors |= dec[i] != plain[i];

    xtea_setkey(&tfm, key, sizeof(key));
    xeta_encrypt(&tfm, enc, plain);
    xeta_decrypt(&tfm, dec, enc);
    for (i = 0; i < XTEA_BLOCK_SIZE; i++)
        errors |= dec[i] != plain[i];

    return errors + dec[0];