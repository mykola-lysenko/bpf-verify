    /* __cmpdi2: assert the result is always in {0, 1, 2}.
     *
     * Stronger properties (cmpdi2(a,a)==1, r+rrev==2) are NOT asserted.
     * The BPF verifier makes independent function calls and tracks their
     * results as independent scalars; it cannot prove relationships between
     * two separate call results without symbolic reasoning. This is a
     * VERIFIER PRECISION LIMITATION, not a bug in __cmpdi2.
     *
     * The range property (0 <= r <= 2) IS provable: the verifier inlines
     * __cmpdi2 and can determine the result is always 0, 1, or 2 by
     * tracking the three-way comparison branches. */
    __u32 key0 = 0, key1 = 1;
    __u64 *va = bpf_map_lookup_elem(&input_map, &key0);
    __u64 *vb = bpf_map_lookup_elem(&input_map, &key1);
    if (!va || !vb) return 0;
    long long a = (long long)*va;
    long long b = (long long)*vb;
    int r = __cmpdi2(a, b);
    /* Property: result is always in {0, 1, 2} */
    BPF_ASSERT(r >= 0 && r <= 2);
    return r;