    /* drivers/net/ethernet/chelsio/cxgb4/cudbg_common.c: debug-buffer accounting. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0x1020304050607080ULL;
    char outbuf[32];
    char compbuf[16];
    struct cudbg_init init = {};
    struct cudbg_buffer dbg = {};
    struct cudbg_buffer pin = {};
    u32 req = 1 + (u32)((seed >> 32) & 31);
    int ret1;
    int ret2;
    int ret3;

    outbuf[0] = (char)seed;
    compbuf[0] = (char)(seed >> 8);
    init.compress_type = (seed & 0x100) ? CUDBG_COMPRESSION_ZLIB :
                          CUDBG_COMPRESSION_NONE;
    init.compress_buff = compbuf;
    init.compress_buff_size = 8 + (u32)((seed >> 40) & 7);
    dbg.data = outbuf;
    dbg.size = 16 + (u32)((seed >> 16) & 15);
    dbg.offset = (u32)(seed & 15);

    ret1 = cudbg_get_buff(&init, &dbg, req, &pin);
    if (!ret1)
        cudbg_update_buff(&pin, &dbg);

    ret2 = cudbg_get_buff(&init, &dbg, 32, &pin);

    init.compress_type = CUDBG_COMPRESSION_ZLIB;
    ret3 = cudbg_get_buff(&init, &dbg, req, &pin);
    cudbg_put_buff(&init, &pin);

    return ret1 + ret2 + ret3 + dbg.offset + pin.offset + pin.size +
           compbuf[0];
