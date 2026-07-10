
    /* crc16: map-seeded buffer so the CRC loop and table lookup stay live. */
    __u32 key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &key);
    u64 seed = input ? *input : 0x0102030405060708ULL;
    unsigned char buf[4];
    buf[0] = (unsigned char)seed;
    buf[1] = (unsigned char)(seed >> 8);
    buf[2] = (unsigned char)(seed >> 16);
    buf[3] = (unsigned char)(seed >> 24);
    u16 crc = crc16((u16)(seed >> 32), buf, sizeof(buf));
    return (int)crc;
