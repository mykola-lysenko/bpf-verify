    /* bitrev: double-reversal is identity: bitrev32(bitrev32(x)) == x.
     *
     * Execution contract (see targets/README.md): return 0 on success and
     * only ever return non-zero via BPF_ASSERT. Do NOT return a computed
     * value -- the runner treats any non-zero return as a property failure.
     * Map-seeded x keeps the computation live for both the verifier (unknown
     * scalar) and the runner (fuzzed at run time). */
    __u32 key0 = 0;
    __u64 *vx = bpf_map_lookup_elem(&input_map, &key0);
    if (!vx) return 0;
    __u32 x = (__u32)*vx;
    __u32 r  = bitrev32(x);
    __u32 rr = bitrev32(r);
    /* Property: double reversal is identity. */
    BPF_ASSERT(rr == x);
    /* Property: reversal preserves population count. The verifier tracks
     * hweight32(r) and hweight32(x) as independent scalars and cannot prove
     * their equality statically, so it only sees the range bound as provable;
     * the runner executes real values and checks the stronger equality. Both
     * are asserted -- verification still succeeds because returning -1 on the
     * (statically-possible but dynamically-unreachable) mismatch branch is
     * legal. */
    BPF_ASSERT(hweight32(r) <= 32);
    BPF_ASSERT(hweight32(r) == hweight32(x));