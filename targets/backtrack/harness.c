    /* backtrack: scalar precision dependency transfer.
     * Covers jump-history recording/lookup, register and stack dependency
     * propagation through representative BPF instructions, and the
     * conservative all-scalar precision fallback.
     */
    struct bpf_insn insn = {};
    struct bpf_prog prog = {};
    struct bpf_verifier_env env = {};
    struct bpf_verifier_state st = {};
    struct bpf_verifier_state parent = {};
    struct bpf_verifier_state child = {};
    struct bpf_func_state func = {};
    struct bpf_stack_state stack_slots[1] = {};
    struct backtrack_state bt = {};
    struct bpf_jmp_history_entry hist = {};
    u32 history;

    prog.insnsi = &insn;
    prog.len = 1;
    env.prog = &prog;
    env.bpf_capable = true;

    st.first_insn_idx = 0;
    env.insn_idx = 2;
    env.prev_insn_idx = 1;
    BPF_ASSERT(bpf_push_jmp_history(&env, &st, INSN_F_STACK_ACCESS,
                                    1, 0, 0) == 0);
    BPF_ASSERT(st.jmp_history_cnt == 1);
    BPF_ASSERT(st.jmp_history[0].idx == 2);
    BPF_ASSERT(st.jmp_history[0].prev_idx == 1);
    BPF_ASSERT(st.jmp_history[0].flags == INSN_F_STACK_ACCESS);
    BPF_ASSERT(st.jmp_history[0].spi == 1);

    BPF_ASSERT(bpf_push_jmp_history(&env, &st, INSN_F_SRC_REG_STACK,
                                    1, 0, 0) == 0);
    BPF_ASSERT(st.jmp_history_cnt == 1);
    BPF_ASSERT(st.jmp_history[0].flags ==
               (INSN_F_STACK_ACCESS | INSN_F_SRC_REG_STACK));

    env.cur_hist_ent = NULL;
    env.insn_idx = 4;
    env.prev_insn_idx = 2;
    BPF_ASSERT(bpf_push_jmp_history(&env, &st, INSN_F_DST_REG_STACK,
                                    2, 0, 0) == 0);
    BPF_ASSERT(st.jmp_history_cnt == 2);
    BPF_ASSERT(get_jmp_hist_entry(&st, st.jmp_history_cnt, 4) ==
               &st.jmp_history[1]);
    history = st.jmp_history_cnt;
    BPF_ASSERT(get_prev_insn_idx(&st, 4, &history) == 2);
    BPF_ASSERT(history == 1);

    bt.env = &env;
    bt.frame = 0;
    bt.reg_masks[0] = 1U << BPF_REG_2;
    insn = (struct bpf_insn){
        .code = BPF_ALU64 | BPF_MOV | BPF_X,
        .dst_reg = BPF_REG_2, .src_reg = BPF_REG_1,
    };
    BPF_ASSERT(backtrack_insn(&env, 0, -1, NULL, &bt) == 0);
    BPF_ASSERT(!(bt.reg_masks[0] & (1U << BPF_REG_2)));
    BPF_ASSERT(bt.reg_masks[0] & (1U << BPF_REG_1));

    bt_reset(&bt);
    bt.frame = 0;
    bt.reg_masks[0] = 1U << BPF_REG_3;
    hist.flags = INSN_F_STACK_ACCESS;
    hist.spi = 1;
    hist.frame = 0;
    insn = (struct bpf_insn){
        .code = BPF_LDX | BPF_MEM | BPF_DW,
        .dst_reg = BPF_REG_3, .src_reg = BPF_REG_FP, .off = -16,
    };
    BPF_ASSERT(backtrack_insn(&env, 0, -1, &hist, &bt) == 0);
    BPF_ASSERT(!(bt.reg_masks[0] & (1U << BPF_REG_3)));
    BPF_ASSERT(bt.stack_masks[0] & (1ULL << 1));

    bt_reset(&bt);
    bt.frame = 0;
    bt.stack_masks[0] = 1ULL << 1;
    insn = (struct bpf_insn){
        .code = BPF_STX | BPF_MEM | BPF_DW,
        .dst_reg = BPF_REG_FP, .src_reg = BPF_REG_4, .off = -16,
    };
    BPF_ASSERT(backtrack_insn(&env, 0, -1, &hist, &bt) == 0);
    BPF_ASSERT(!(bt.stack_masks[0] & (1ULL << 1)));
    BPF_ASSERT(bt.reg_masks[0] & (1U << BPF_REG_4));

    bt_reset(&bt);
    bt.frame = 1;
    bt.reg_masks[1] = 1U << BPF_REG_5;
    hist.flags = INSN_F_STACK_ARG_ACCESS;
    hist.spi = 0;
    hist.frame = 1;
    insn = (struct bpf_insn){
        .code = BPF_LDX | BPF_MEM | BPF_DW,
        .dst_reg = BPF_REG_5, .src_reg = BPF_REG_FP, .off = -8,
    };
    BPF_ASSERT(backtrack_insn(&env, 0, -1, &hist, &bt) == 0);
    BPF_ASSERT(bt.stack_arg_masks[0] & 1);

    bt_reset(&bt);
    bt.frame = 0;
    bt.reg_masks[0] = 1U << BPF_REG_5;
    insn = (struct bpf_insn){
        .code = BPF_JMP | BPF_JGT | BPF_X,
        .dst_reg = BPF_REG_5, .src_reg = BPF_REG_6,
    };
    BPF_ASSERT(backtrack_insn(&env, 0, -1, NULL, &bt) == 0);
    BPF_ASSERT(bt.reg_masks[0] & (1U << BPF_REG_5));
    BPF_ASSERT(bt.reg_masks[0] & (1U << BPF_REG_6));

    func.regs[BPF_REG_1].type = SCALAR_VALUE;
    func.regs[BPF_REG_2].type = SCALAR_VALUE;
    func.regs[BPF_REG_2].precise = true;
    func.stack = stack_slots;
    func.allocated_stack = BPF_REG_SIZE;
    stack_slots[0].slot_type[BPF_REG_SIZE - 1] = STACK_SPILL;
    stack_slots[0].spilled_ptr.type = SCALAR_VALUE;

    parent.curframe = 0;
    parent.frame[0] = &func;
    child.parent = &parent;
    child.curframe = 0;
    child.frame[0] = &func;
    bpf_mark_all_scalars_precise(&env, &child);
    BPF_ASSERT(func.regs[BPF_REG_1].precise);
    BPF_ASSERT(stack_slots[0].spilled_ptr.precise);

    return (int)(st.jmp_history_cnt + bt.reg_masks[0]);
