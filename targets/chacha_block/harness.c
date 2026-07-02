
    /* chacha_block: test chacha_permute via chacha_block_generic */
    struct chacha_state state;
    __builtin_memset(&state, 0, sizeof(state));
    u8 out[64];
    chacha_block_generic(&state, out, 20);
    (void)out[0];
    return 0;
