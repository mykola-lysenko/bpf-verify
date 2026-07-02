    /* net/ceph/crush/hash.c: pure Jenkins hash helpers. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0x1122334455667788ULL;
    u32 a = (u32)seed;
    u32 b = (u32)(seed >> 13);
    u32 c = (u32)(seed >> 27);
    u32 d = (u32)(seed >> 41);
    u32 h1 = crush_hash32(CRUSH_HASH_RJENKINS1, a);
    u32 h2 = crush_hash32_2(CRUSH_HASH_RJENKINS1, a, b);
    u32 h3 = crush_hash32_3(CRUSH_HASH_RJENKINS1, a, b, c);
    u32 h4 = crush_hash32_4(CRUSH_HASH_RJENKINS1, a, b, c, d);
    u32 bad = crush_hash32(99, a);

    return (int)(h1 ^ h2 ^ h3 ^ h4 ^ bad);