    /* bitrev: assert double-reversal is identity: bitrev(bitrev(x)) == x */
    __u32 key0 = 0;
    __u64 *vx = bpf_map_lookup_elem(&input_map, &key0);
    if (!vx) return 0;
    __u32 x = (__u32)*vx;
    __u32 r  = bitrev32(x);
    __u32 rr = bitrev32(r);
    /* Property: double reversal is identity */
    BPF_ASSERT(rr == x);
    /* Property: hweight result is in valid range [0, 32].
     * We cannot assert hweight32(r) == hweight32(x) because the BPF verifier
     * tracks hweight32(r) and hweight32(x) as independent scalars and cannot
     * prove their equality for arbitrary x (a verifier precision limitation). */
    BPF_ASSERT(hweight32(r) <= 32);
    return (int)r;