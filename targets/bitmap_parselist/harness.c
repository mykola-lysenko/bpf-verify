    /* DOCUMENTED VERIFIER BOUNDARY (expect_failure target).
     *
     * bitmap_parselist()'s static helpers (bitmap_find_region, bitmap_getnum,
     * bitmap_parse_region) return a const char* cursor into the caller's input
     * buffer -- which lives on the harness stack. As out-of-line BPF
     * subprograms this trips the verifier's "cannot return stack pointer to
     * the caller" rule. And force-inlining the whole call graph instead
     * (-mllvm -inline-threshold=100000) trades this for "The sequence of 8193
     * jumps is too complex", so the parser is caught between two boundaries.
     * Pinned here as a regression-guarded characterization; if this ever
     * verifies, a boundary was lifted (see check_results.py).
     *
     * The harness stages a small "0-N,M" range list with map-seeded digits so
     * the parse loop runs live up to the rejected return. */
    __u32 k0 = 0, k1 = 1;
    __u64 *a = bpf_map_lookup_elem(&input_map, &k0);
    __u64 *b = bpf_map_lookup_elem(&input_map, &k1);

    char buf[8];
    buf[0] = '0';
    buf[1] = '-';
    buf[2] = '0' + (char)((a ? *a : 3) & 3);   /* range end 0..3 */
    buf[3] = ',';
    buf[4] = '0' + (char)((b ? *b : 5) & 7);   /* single bit 0..7 */
    buf[5] = '\0';

    unsigned long mask[1];   /* DECLARE_BITMAP(mask, 64) */
    int ret = bitmap_parselist(buf, mask, 64);
    return ret;
