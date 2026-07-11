    /* crc7_be: 7-bit CRC. Map-seeded buffer keeps the table lookup live. */
    __u32 k0 = 0, k1 = 1;
    __u64 *a = bpf_map_lookup_elem(&input_map, &k0);
    __u64 *b = bpf_map_lookup_elem(&input_map, &k1);
    u64 seed = a ? *a : 0x01020304ULL;
    __u8 buf[4] = {
        (__u8)seed, (__u8)(seed >> 8), (__u8)(seed >> 16), (__u8)(seed >> 24),
    };
    return (int)crc7_be((__u8)(b ? *b : 0), buf, sizeof(buf));
