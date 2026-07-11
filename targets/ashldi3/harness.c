    /* __ashldi3: 64-bit arithmetic shift left. Seed value + count so the
     * shift is not constant-folded away. */
    __u32 k0 = 0, k1 = 1;
    __u64 *a = bpf_map_lookup_elem(&input_map, &k0);
    __u64 *b = bpf_map_lookup_elem(&input_map, &k1);
    long long val = a ? (long long)*a : 1;
    int cnt = (int)((b ? *b : 10) & 63);
    return (int)__ashldi3(val, cnt);
