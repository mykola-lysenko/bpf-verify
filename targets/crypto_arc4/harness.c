    /* crypto/arc4.c: exercise lskcipher setkey/init and continuation crypt wrapper. */
    struct crypto_lskcipher tfm = {};
    u8 key[16];
    u8 plain[8];
    u8 out[8];
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0x0f1e2d3c4b5a6978ULL;
    int i;

    for (i = 0; i < 16; i++)
        key[i] = (u8)(seed >> ((i & 7) * 8)) ^ (u8)(i + 1);
    for (i = 0; i < 8; i++)
        plain[i] = (u8)(seed >> ((i & 7) * 8)) ^ (u8)(0x80 + i);

    crypto_arc4_init(&tfm);
    crypto_arc4_setkey(&tfm, key, sizeof(key));
    crypto_arc4_crypt(&tfm, plain, out, 0,
                      (u8 *)&__bpf_arc4_siv, CRYPTO_LSKCIPHER_FLAG_CONT);
    return key[0];
