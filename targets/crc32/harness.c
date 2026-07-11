    /* crc32: map-seeded buffer + init so crc32_le/crc32_be stay live; return
     * their xor so both computations are observed. */
    __u32 k0 = 0, k1 = 1;
    __u64 *a = bpf_map_lookup_elem(&input_map, &k0);
    __u64 *b = bpf_map_lookup_elem(&input_map, &k1);
    u64 seed = a ? *a : 0xDEADBEEFULL;
    u32 init = (u32)(b ? *b : 0);
    unsigned char data[4] = {
        (unsigned char)seed, (unsigned char)(seed >> 8),
        (unsigned char)(seed >> 16), (unsigned char)(seed >> 24),
    };
    u32 le = crc32_le(init, data, sizeof(data));
    u32 be = crc32_be(init, data, sizeof(data));
    return (int)(le ^ be);
