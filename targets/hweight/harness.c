    /* hweight: assert result is in [0, bitwidth].
     *
     * The complement property (w32 + wc32 == 32) is NOT asserted here.
     * The BPF verifier tracks w32 and wc32 as independent scalars
     * (each in [0..32]) and cannot prove their sum equals exactly 32
     * without symbolic algebraic reasoning. This is a VERIFIER PRECISION
     * LIMITATION, not a bug in hweight.
     *
     * The range assertions (w32 <= 32, w64 <= 64) ARE provable: the
     * verifier tracks the bit-manipulation steps of hweight and can
     * determine the result fits in [0..bitwidth]. */
    __u32 key0 = 0;
    __u64 *vx = bpf_map_lookup_elem(&input_map, &key0);
    if (!vx) return 0;
    __u32 x32 = (__u32)*vx;
    __u64 x64 = *vx;
    unsigned int w32 = hweight32(x32);
    unsigned long w64 = hweight64(x64);
    /* Property: result is in valid range [0, bitwidth] */
    BPF_ASSERT(w32 <= 32);
    BPF_ASSERT(w64 <= 64);
    return (int)(w32 + (int)w64);
