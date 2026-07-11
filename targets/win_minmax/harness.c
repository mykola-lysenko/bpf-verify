    /* win_minmax: seed the reset value and measurements so the running
     * min/max tracking is not constant-folded. */
    __u32 k0 = 0, k1 = 1, k2 = 2;
    __u64 *a = bpf_map_lookup_elem(&input_map, &k0);
    __u64 *b = bpf_map_lookup_elem(&input_map, &k1);
    __u64 *c = bpf_map_lookup_elem(&input_map, &k2);
    struct minmax m;
    u32 t0 = (u32)(a ? *a : 0);
    minmax_reset(&m, t0, (u32)(b ? *b : 1000));
    u32 v = minmax_running_min(&m, 100, t0 + 1, (u32)(c ? *c : 50));
    u32 w = minmax_running_max(&m, 100, t0 + 2, (u32)(c ? *c : 2000));
    return (int)(v + w + minmax_get(&m));
