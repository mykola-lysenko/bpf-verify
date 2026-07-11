    /* intlog2/intlog10: fixed-point logarithms. Seed the argument so the
     * lookup/interpolation stays live; return both. */
    __u32 k0 = 0;
    __u64 *a = bpf_map_lookup_elem(&input_map, &k0);
    u32 v = (u32)(a ? *a : 8);
    if (v == 0) v = 1;
    return (int)(intlog2(v) ^ intlog10(v));
