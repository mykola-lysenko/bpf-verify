
    /* crypto_utils: __crypto_xor test */
    __u32 key0 = 0, key1 = 1;
    __u64 *va = bpf_map_lookup_elem(&input_map, &key0);
    __u64 *vb = bpf_map_lookup_elem(&input_map, &key1);
    if (!va || !vb) return 0;
    u64 a = *va;
    u64 b = *vb;
    u64 dst = 0;
    __crypto_xor((u8 *)&dst, (const u8 *)&a, (const u8 *)&b, sizeof(dst));
    return (int)dst;
