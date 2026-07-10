    /* liveness_call_summary: record_call_access() stack-arg loop coverage.
     *
     * The pre-include makes bpf_get_call_summary() report seven parameters.
     * Only outgoing stack arg slot 1 is FP-derived, so the SPIS_ALL assertions
     * below prove that record_call_access() reached the >5-arg loop.
     */
    __u32 key = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &key);
    if (!vp) return 0;

    /* Keep only env->prog on stack; the access helper only reads that field. */
    struct {
        struct bpf_prog *prog;
    } env_storage = {};
    struct bpf_prog prog = {};
    struct bpf_verifier_env *env = (struct bpf_verifier_env *)&env_storage;
    struct bpf_insn insn = {};
    struct func_instance inst = {};
    struct per_frame_masks *masks;
    struct arg_track at[MAX_AT_TRACK_REGS];

    prog.insnsi = &insn;
    prog.len = 1;
    env->prog = &prog;

    inst.depth = 1;
    inst.subprog_start = 0;
    inst.insn_cnt = 1;

    __bpf_liveness_call_summary_reset_at(at);
    at[MAX_BPF_REG + 1] = (struct arg_track){
        .off = { -32 },
        .frame = 0,
        .off_cnt = 1,
    };
    insn = (struct bpf_insn){
        .code = BPF_JMP | BPF_CALL,
        .src_reg = BPF_REG_7,
    };

    BPF_ASSERT(record_call_access(env, &inst, at, 0) == 0);
    masks = get_frame_masks(&inst, 0, 0);
    BPF_ASSERT(masks && spis_equal(masks->may_read, SPIS_ALL));
    masks = get_frame_masks(&inst, 1, 0);
    BPF_ASSERT(masks && spis_equal(masks->may_read, SPIS_ALL));

    return (int)(*vp & 1);
