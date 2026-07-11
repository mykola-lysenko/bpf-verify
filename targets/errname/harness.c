    /* errname: map an errno to its symbolic string. Seed the code so the bounds
     * check + table lookup stay live; compare pointers from two lookups (no
     * deref of the returned .rodata pointer, which the verifier will not
     * track). */
    __u32 k0 = 0, k1 = 1;
    __u64 *a = bpf_map_lookup_elem(&input_map, &k0);
    __u64 *b = bpf_map_lookup_elem(&input_map, &k1);
    const char *n1 = errname((int)(a ? *a : -22));
    const char *n2 = errname((int)(b ? *b : -2));
    return (int)(n1 != n2);
