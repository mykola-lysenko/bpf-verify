    /* memneq: compare two dynamic words through __crypto_memneq. */
    __u32 key0 = 0, key1 = 1;
    __u64 *va = bpf_map_lookup_elem(&input_map, &key0);
    __u64 *vb = bpf_map_lookup_elem(&input_map, &key1);
    if (!va || !vb) return 0;
    u64 a = *va;
    u64 b = *vb;
    return __crypto_memneq(&a, &b, sizeof(a)) ? 1 : 0;
