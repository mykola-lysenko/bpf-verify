    /* DOCUMENTED VERIFIER BOUNDARY (expect_failure target).
     *
     * gcd() on SYMBOLIC operands is rejected with "The sequence of 8193 jumps
     * is too complex" -- the jump-history complexity limit, the 5th distinct
     * boundary class in the catalog. The binary-GCD loop's data-dependent
     * branches accumulate in the verifier's jump history regardless of how
     * narrowly the inputs are masked: 32-bit, 16-bit and 8-bit operands all
     * fail identically (~41k insns processed), because value ranges do not
     * bound the loop's termination proof. The plain `gcd` coverage target
     * passes only because its literal inputs let clang constant-fold the
     * whole loop away; this target pins what happens on real (unknown) data.
     * If it ever verifies, the verifier learned to bound value-dependent
     * loops -- promote it. Operands: a odd (fast path), b nonzero (the
     * even-normalization loop is genuinely infinite for b == 0, a separate
     * rejection). */
    __u32 k0 = 0, k1 = 1;
    __u64 *pa = bpf_map_lookup_elem(&input_map, &k0);
    __u64 *pb = bpf_map_lookup_elem(&input_map, &k1);

    unsigned long a = (unsigned long)(((__u32)(pa ? *pa : 21) & 0xff) | 1);
    unsigned long b = (unsigned long)(((__u32)(pb ? *pb : 6) & 0xff) | 4);

    return (int)gcd(a, b);
