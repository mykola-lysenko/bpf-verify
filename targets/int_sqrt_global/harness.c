    /* DOCUMENTED VERIFIER BOUNDARY (expect_failure target).
     *
     * With .BTF.ext kept, int_sqrt (EXPORT_SYMBOL, external linkage) becomes a
     * BPF GLOBAL FUNCTION: verified once, independently, for ALL inputs
     * described by its BTF -- not against the harness's concrete argument.
     * Its bit-loop explored over an unconstrained u64 blows the 1M-insn
     * verifier budget: "BPF program is too large. Processed 1000001 insn".
     *
     * The contrast target is plain int_sqrt (same source, .BTF.ext stripped):
     * as a static subprogram in the caller's context it verifies easily. The
     * pair pins the cost of all-inputs generality vs concrete-context
     * tractability -- see analysis/global_functions_and_inlining.md. If this
     * ever verifies, the verifier got dramatically better at bounded-loop
     * analysis; promote the target. */
    __u32 k0 = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &k0);
    unsigned long r = int_sqrt(vp ? (unsigned long)*vp : 0);
    return (int)r;
