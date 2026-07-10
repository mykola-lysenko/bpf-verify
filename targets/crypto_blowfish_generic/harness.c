    /* crypto/blowfish_generic.c: exercise setkey plus encrypt/decrypt round trip.
     *
     * bf_ctx contains a 4 KiB S-box, so the crypto_tfm lives in static storage
     * through the target-specific preinclude rather than on the BPF stack. */
    static struct crypto_tfm tfm;
    static const u8 key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    static const u8 plain[BF_BLOCK_SIZE] = {
        0x42, 0x50, 0x46, 0x2d, 0x76, 0x65, 0x72, 0x69,
    };
    u8 enc[BF_BLOCK_SIZE];
    u8 dec[BF_BLOCK_SIZE];
    int i;

    BPF_ASSERT(blowfish_setkey(&tfm, key, sizeof(key)) == 0);
    bf_encrypt(&tfm, enc, plain);
    bf_decrypt(&tfm, dec, enc);
    for (i = 0; i < BF_BLOCK_SIZE; i++)
        BPF_ASSERT(dec[i] == plain[i]);

    return enc[0];
