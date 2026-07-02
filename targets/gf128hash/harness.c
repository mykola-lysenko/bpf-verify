    /* GHASH over one dynamic block, using the generic GF(2^128) path. */
    __u32 map_key = 0;
    __u64 *v = bpf_map_lookup_elem(&input_map, &map_key);
    if (!v) return 0;
    struct ghash_key gkey;
    struct ghash_ctx gctx = {0};
    u8 raw[GHASH_BLOCK_SIZE] = {0};
    u8 data[GHASH_BLOCK_SIZE] = {0};
    u8 out[GHASH_BLOCK_SIZE];
    *(__u64 *)&raw[0] = *v;
    *(__u64 *)&data[0] = *v >> 1;
    ghash_preparekey(&gkey, raw);
    gctx.key = &gkey;
    ghash_update(&gctx, data, sizeof(data));
    ghash_final(&gctx, out);
    return out[0];