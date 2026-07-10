    /* drivers/media/test-drivers/vidtv/vidtv_common.c: bounded memcpy/memset wrappers. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0x0102030405060708ULL;
    u8 dst[16] = {};
    u8 src[8];
    size_t copy_off = 2;
    size_t copy_len = 1 + ((seed >> 8) & 7);
    size_t set_off = 6;
    size_t set_len = 1 + ((seed >> 24) & 7);
    size_t edge_off = 12;
    u32 copied;
    u32 skipped_copy;
    u32 set;
    u32 skipped_set;

    src[0] = (u8)seed;
    src[1] = (u8)(seed >> 8);
    src[2] = (u8)(seed >> 16);
    src[3] = (u8)(seed >> 24);
    src[4] = (u8)(seed >> 32);
    src[5] = (u8)(seed >> 40);
    src[6] = (u8)(seed >> 48);
    src[7] = (u8)(seed >> 56);

    copied = vidtv_memcpy(dst, copy_off, sizeof(dst), src, copy_len);
    skipped_copy = vidtv_memcpy(dst, edge_off, sizeof(dst), src, 8);
    set = vidtv_memset(dst, set_off, sizeof(dst), (int)(seed >> 40), set_len);
    skipped_set = vidtv_memset(dst, edge_off, sizeof(dst), 0xff, 8);

    return (int)(copied + skipped_copy + set + skipped_set + dst[2] + dst[6]);
