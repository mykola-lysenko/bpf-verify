    /* Call a 6-argument static subprogram (the 6th passes on the stack) and use
     * the result. If >5-arg static-subprogram support regresses, this fails at
     * compile (LLVM backend) or verify (stack-arg read) -- a regression detector
     * for that toolchain feature. Needs clang 23+ and keep_btf_ext. */
    __u32 k0 = 0, k1 = 1;
    __u64 *p = bpf_map_lookup_elem(&input_map, &k0);
    __u64 *q = bpf_map_lookup_elem(&input_map, &k1);
    long v = p ? (long)*p : 1, w = q ? (long)*q : 2;
    return (int)bpf_stack_arg_selftest(v, w, v + 1, w + 1, v + 2, w + 2);
