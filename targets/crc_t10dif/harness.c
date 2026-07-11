    /* crc_t10dif_update: T10-DIF CRC. Map-seeded buffer + init keep it live. */
    __u32 k0 = 0, k1 = 1;
    __u64 *a = bpf_map_lookup_elem(&input_map, &k0);
    __u64 *b = bpf_map_lookup_elem(&input_map, &k1);
    u64 seed = a ? *a : 0xDEADBEEFULL;
    unsigned char data[4] = {
        (unsigned char)seed, (unsigned char)(seed >> 8),
        (unsigned char)(seed >> 16), (unsigned char)(seed >> 24),
    };
    return (int)crc_t10dif_update((u16)(b ? *b : 0), data, sizeof(data));
