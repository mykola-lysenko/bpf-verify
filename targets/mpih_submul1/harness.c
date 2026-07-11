    /* mpihelp_submul_1: multiply-subtract a limb vector. Seed operands and
     * return the result + borrow so the multiply loop stays live. */
    __u32 k0 = 0, k1 = 1;
    __u64 *a = bpf_map_lookup_elem(&input_map, &k0);
    __u64 *b = bpf_map_lookup_elem(&input_map, &k1);
    unsigned long res[2] = { (unsigned long)(a ? *a : 1000), 0 };
    unsigned long s1[2]  = { (unsigned long)(b ? *b : 3), 1 };
    unsigned long borrow = mpihelp_submul_1(res, s1, 2, (unsigned long)(a ? *a : 5));
    return (int)(res[0] ^ res[1] ^ borrow);
