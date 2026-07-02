    /* crc_itu_t: map-seeded buffer so the CRC loop and table lookup stay live. */
    __u32 key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &key);
    u64 seed = input ? *input : 0x8877665544332211ULL;
    __u8 buf[4];
    buf[0] = (__u8)seed;
    buf[1] = (__u8)(seed >> 8);
    buf[2] = (__u8)(seed >> 16);
    buf[3] = (__u8)(seed >> 24);
    __u16 crc = crc_itu_t((__u16)(seed >> 32), buf, sizeof(buf));
    return (int)crc;