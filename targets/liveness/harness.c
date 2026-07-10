    /* liveness: verifier liveness helpers.
     *
     * Keep this target on BPF-safe call shapes: build arg_track values
     * directly instead of calling struct-returning helpers.
     */
    __u32 key = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &key);
    if (!vp) return 0;

    /* Keep only env->prog on stack; the access helpers do not need the rest. */
    struct {
        struct bpf_prog *prog;
    } env_storage = {};
    struct bpf_prog prog = {};
    struct bpf_verifier_env *env = (struct bpf_verifier_env *)&env_storage;
    struct bpf_insn insns[8] = {};
    struct insn_live_regs live = {};
    struct func_instance inst = {};
    struct per_frame_masks *masks;
    struct arg_track at[MAX_AT_TRACK_REGS];
    s16 out = 0;
    int ret = 0;

    insns[0] = (struct bpf_insn){
        .code = BPF_JMP | BPF_JA,
        .off = 2,
        .imm = 4,
    };
    insns[1] = (struct bpf_insn){
        .code = BPF_JMP32 | BPF_JA,
        .imm = -1,
    };
    BPF_ASSERT(bpf_jmp_offset(&insns[0]) == 2);
    BPF_ASSERT(bpf_jmp_offset(&insns[1]) == -1);

    BPF_PROVE(stack_arg_off_to_slot(8) == 0);
    BPF_PROVE(stack_arg_off_to_slot(56) == 6);
    BPF_PROVE(stack_arg_off_to_slot(64) == -1);
    BPF_PROVE(stack_arg_off_to_slot(0) == -1);
    BPF_PROVE(fp_off_to_slot(-8) == 0);
    BPF_PROVE(fp_off_to_slot(-512) == 63);
    BPF_PROVE(fp_off_to_slot(-4) == -1);
    BPF_PROVE(!arg_add(-32, 24, &out) && out == -8);

    insns[2] = (struct bpf_insn){
        .code = BPF_ALU64 | BPF_MOV | BPF_K,
        .dst_reg = BPF_REG_6,
    };
    compute_insn_live_regs(env, &insns[2], &live);
    BPF_ASSERT(live.def == BIT(BPF_REG_6) && live.use == 0);

    insns[3] = (struct bpf_insn){
        .code = BPF_LDX | BPF_MEM | BPF_DW,
        .dst_reg = BPF_REG_1,
        .src_reg = BPF_REG_10,
    };
    compute_insn_live_regs(env, &insns[3], &live);
    BPF_ASSERT(live.def == BIT(BPF_REG_1) && live.use == BIT(BPF_REG_10));

    insns[4] = (struct bpf_insn){
        .code = BPF_JMP | BPF_CALL,
    };
    compute_insn_live_regs(env, &insns[4], &live);
    BPF_ASSERT(live.def == GENMASK(CALLER_SAVED_REGS - 1, 0));
    BPF_ASSERT(live.use == GENMASK(MAX_BPF_FUNC_REG_ARGS, 1));

    prog.insnsi = insns;
    prog.len = 8;
    env->prog = &prog;

    inst.depth = 1;
    inst.subprog_start = 0;
    inst.insn_cnt = 8;
    BPF_ASSERT(record_stack_access_off(&inst, -8, 8, 0, 0) == 0);
    BPF_ASSERT(record_stack_access_off(&inst, -8, -8, 0, 1) == 0);

    masks = get_frame_masks(&inst, 0, 0);
    BPF_ASSERT(masks && spis_test_bit(masks->may_read, 0) &&
               spis_test_bit(masks->may_read, 1));

    masks = get_frame_masks(&inst, 0, 1);
    BPF_ASSERT(masks && spis_test_bit(masks->must_write, 0) &&
               spis_test_bit(masks->must_write, 1));

    __bpf_liveness_reset_at(at);
    at[BPF_REG_10] = (struct arg_track){
        .off = { 0 },
        .frame = 0,
        .off_cnt = 1,
    };
    insns[2] = (struct bpf_insn){
        .code = BPF_LDX | BPF_MEM | BPF_DW,
        .dst_reg = BPF_REG_1,
        .src_reg = BPF_REG_10,
        .off = -16,
    };
    BPF_ASSERT(record_load_store_access(env, &inst, at, 2) == 0);
    masks = get_frame_masks(&inst, 0, 2);
    BPF_ASSERT(masks && spis_test_bit(masks->may_read, 2) &&
               spis_test_bit(masks->may_read, 3));

    insns[3] = (struct bpf_insn){
        .code = BPF_STX | BPF_MEM | BPF_DW,
        .dst_reg = BPF_REG_10,
        .src_reg = BPF_REG_1,
        .off = -24,
    };
    BPF_ASSERT(record_load_store_access(env, &inst, at, 3) == 0);
    masks = get_frame_masks(&inst, 0, 3);
    BPF_ASSERT(masks && spis_test_bit(masks->must_write, 4) &&
               spis_test_bit(masks->must_write, 5));

    BPF_ASSERT(record_imprecise(&inst, BIT(0) | BIT(1), 4) == 0);
    masks = get_frame_masks(&inst, 0, 4);
    BPF_ASSERT(masks && spis_equal(masks->may_read, SPIS_ALL));
    masks = get_frame_masks(&inst, 1, 4);
    BPF_ASSERT(masks && spis_equal(masks->may_read, SPIS_ALL));

    __bpf_liveness_reset_at(at);
    at[BPF_REG_1] = (struct arg_track){
        .off = { -32 },
        .frame = 0,
        .off_cnt = 1,
    };
    insns[5] = (struct bpf_insn){
        .code = BPF_JMP | BPF_CALL,
        .src_reg = BPF_REG_7,
    };
    BPF_ASSERT(record_call_access(env, &inst, at, 5) == 0);
    masks = get_frame_masks(&inst, 0, 5);
    BPF_ASSERT(masks && spis_equal(masks->may_read, SPIS_ALL));
    masks = get_frame_masks(&inst, 1, 5);
    BPF_ASSERT(masks && spis_equal(masks->may_read, SPIS_ALL));

    __bpf_liveness_reset_at(at);
    at[BPF_REG_3] = (struct arg_track){
        .off = { -40, -48 },
        .frame = 0,
        .off_cnt = 2,
    };
    insns[6] = (struct bpf_insn){
        .code = BPF_STX | BPF_MEM | BPF_W,
        .dst_reg = BPF_REG_3,
        .src_reg = BPF_REG_1,
    };
    BPF_ASSERT(record_load_store_access(env, &inst, at, 6) == 0);
    masks = get_frame_masks(&inst, 0, 6);
    BPF_ASSERT(masks && spis_is_zero(masks->must_write));

    ret += live.def + (int)out + (int)(*vp & 1);
    return ret;
