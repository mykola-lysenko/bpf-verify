    /* DOCUMENTED VERIFIER BOUNDARY (expect_failure target).
     *
     * bm_find() fetches text through conf->get_next_block(...) -- an indirect
     * call through a struct function pointer, the standard kernel callback
     * idiom (textsearch, notifier chains, ops tables). clang compiles a
     * genuinely indirect call to the callx instruction (opcode 0x8d), which
     * the verifier REJECTS outright: "unknown opcode 8d". Pinned here as a
     * regression-guarded characterization; if this ever verifies, indirect
     * calls landed in the verifier (a major feature) -- promote the target.
     *
     * Two subtleties this target encodes:
     * - keep_btf_ext is required: with .BTF.ext stripped (pipeline default),
     *   taking a function's address fails earlier with "missing btf
     *   func_info" -- an artifact of our strip, not the intrinsic boundary.
     * - the callback must be RUNTIME-selected (two candidates, map-chosen):
     *   with a single statically-known callback clang devirtualizes the call
     *   and the program VERIFIES (measured: success, 10 insns). */
    __u32 k0 = 0;
    __u64 *sel = bpf_map_lookup_elem(&input_map, &k0);
    __bpf_bm_area.conf.get_next_block =
        (sel && (*sel & 1)) ? __bpf_next_block_a : __bpf_next_block_b;
    __bpf_bm_area.bm.patlen = 1;
    __bpf_bm_area.bm.pattern = __bpf_bm_area.pat;
    struct ts_state st = {};
    unsigned int r = bm_find(&__bpf_bm_area.conf, &st);
    return (int)r;
