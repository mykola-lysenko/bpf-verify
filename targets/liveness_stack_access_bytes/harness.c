    /* liveness_stack_access_bytes: helper/kfunc stack access byte hooks.
     *
     * Harness-local overrides make helper calls return read byte counts and
     * kfunc calls return write byte counts. The mask assertions prove those
     * hook results flow through record_arg_access().
     */
    __u32 key = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &key);
    if (!vp) return 0;

    struct bpf_verifier_env env = {};
    struct bpf_insn helper = {};
    struct bpf_insn kfunc = {};
    struct func_instance inst = {};
    struct per_frame_masks *masks;
    struct arg_track helper_arg = {};
    struct arg_track kfunc_arg = {};

    inst.depth = 0;
    inst.subprog_start = 0;
    inst.insn_cnt = 2;

    helper_arg = (struct arg_track){
        .off = { -16 },
        .frame = 0,
        .off_cnt = 1,
    };
    helper = (struct bpf_insn){
        .code = BPF_JMP | BPF_CALL,
    };
    BPF_ASSERT(record_arg_access(&env, &inst, &helper, &helper_arg, 0, 0) == 0);
    masks = get_frame_masks(&inst, 0, 0);
    BPF_ASSERT(masks && spis_test_bit(masks->may_read, 2) &&
               spis_test_bit(masks->may_read, 3) &&
               spis_is_zero(masks->must_write));

    kfunc_arg = (struct arg_track){
        .off = { -24 },
        .frame = 0,
        .off_cnt = 1,
    };
    kfunc = (struct bpf_insn){
        .code = BPF_JMP | BPF_CALL,
        .src_reg = BPF_PSEUDO_KFUNC_CALL,
    };
    BPF_ASSERT(record_arg_access(&env, &inst, &kfunc, &kfunc_arg, 0, 1) == 0);
    masks = get_frame_masks(&inst, 0, 1);
    BPF_ASSERT(masks && spis_test_bit(masks->must_write, 4) &&
               spis_test_bit(masks->must_write, 5) &&
               spis_is_zero(masks->may_read));

    return (int)(*vp & 1);
