    /* backtrack_insn_prove: verifier-enforced transfer cases.
     *
     * The target-local pre-include forces backtrack_insn() inline so BPF_PROVE
     * can see how each representative instruction transfers precision marks.
     * A map-selected branch keeps all cases reachable in one verifier program.
     */
    __u32 key = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &key);
    if (!vp) return 0;

    struct bpf_insn insns[2] = {};
    struct bpf_prog prog = {};
    struct bpf_verifier_env env = {};
    struct backtrack_state bt = { .env = &env };
    struct bpf_jmp_history_entry hist = {};
    u32 sel = (u32)(*vp & 7);
    u64 ret = 0;

    prog.insnsi = insns;
    prog.len = 2;
    env.prog = &prog;

    if (sel == 0) {
        bt.frame = 0;
        bt.reg_masks[0] = 1U << BPF_REG_2;
        insns[0] = (struct bpf_insn){
            .code = BPF_ALU64 | BPF_MOV | BPF_X,
            .dst_reg = BPF_REG_2,
            .src_reg = BPF_REG_1,
        };
        BPF_PROVE(backtrack_insn(&env, 0, -1, NULL, &bt) == 0);
        BPF_PROVE(bt.reg_masks[0] == (1U << BPF_REG_1));
        BPF_PROVE(bt.stack_masks[0] == 0);
        ret = bt.reg_masks[0];
    } else if (sel == 1) {
        bt.frame = 0;
        bt.reg_masks[0] = 1U << BPF_REG_3;
        hist.flags = INSN_F_STACK_ACCESS;
        hist.spi = 1;
        hist.frame = 0;
        insns[0] = (struct bpf_insn){
            .code = BPF_LDX | BPF_MEM | BPF_DW,
            .dst_reg = BPF_REG_3,
            .src_reg = BPF_REG_FP,
            .off = -16,
        };
        BPF_PROVE(backtrack_insn(&env, 0, -1, &hist, &bt) == 0);
        BPF_PROVE(bt.reg_masks[0] == 0);
        BPF_PROVE(bt.stack_masks[0] == (1ULL << 1));
        ret = bt.stack_masks[0];
    } else if (sel == 2) {
        bt.frame = 0;
        bt.stack_masks[0] = 1ULL << 1;
        hist.flags = INSN_F_STACK_ACCESS;
        hist.spi = 1;
        hist.frame = 0;
        insns[0] = (struct bpf_insn){
            .code = BPF_STX | BPF_MEM | BPF_DW,
            .dst_reg = BPF_REG_FP,
            .src_reg = BPF_REG_4,
            .off = -16,
        };
        BPF_PROVE(backtrack_insn(&env, 0, -1, &hist, &bt) == 0);
        BPF_PROVE(bt.stack_masks[0] == 0);
        BPF_PROVE(bt.reg_masks[0] == (1U << BPF_REG_4));
        ret = bt.reg_masks[0];
    } else if (sel == 3) {
        bt.frame = 0;
        bt.reg_masks[0] = 1U << BPF_REG_5;
        insns[0] = (struct bpf_insn){
            .code = BPF_JMP | BPF_JGT | BPF_X,
            .dst_reg = BPF_REG_5,
            .src_reg = BPF_REG_6,
        };
        BPF_PROVE(backtrack_insn(&env, 0, -1, NULL, &bt) == 0);
        BPF_PROVE(bt.reg_masks[0] ==
                  ((1U << BPF_REG_5) | (1U << BPF_REG_6)));
        BPF_PROVE(bt.stack_masks[0] == 0);
        ret = bt.reg_masks[0];
    } else if (sel == 4) {
        bt.frame = 1;
        bt.reg_masks[1] = 1U << BPF_REG_5;
        hist.flags = INSN_F_STACK_ARG_ACCESS;
        hist.spi = 0;
        hist.frame = 1;
        insns[0] = (struct bpf_insn){
            .code = BPF_LDX | BPF_MEM | BPF_DW,
            .dst_reg = BPF_REG_5,
            .src_reg = BPF_REG_FP,
            .off = -8,
        };
        BPF_PROVE(backtrack_insn(&env, 0, -1, &hist, &bt) == 0);
        BPF_PROVE(bt.reg_masks[1] == 0);
        BPF_PROVE(bt.stack_arg_masks[0] == 1);
        ret = bt.stack_arg_masks[0];
    } else if (sel == 5) {
        bt.frame = 1;
        bt.stack_arg_masks[1] = 1U << 2;
        hist.flags = INSN_F_STACK_ARG_ACCESS;
        hist.spi = 2;
        hist.frame = 1;
        insns[0] = (struct bpf_insn){
            .code = BPF_STX | BPF_MEM | BPF_DW,
            .dst_reg = BPF_REG_FP,
            .src_reg = BPF_REG_4,
            .off = -24,
        };
        BPF_PROVE(backtrack_insn(&env, 0, -1, &hist, &bt) == 0);
        BPF_PROVE(bt.stack_arg_masks[1] == 0);
        BPF_PROVE(bt.reg_masks[1] == (1U << BPF_REG_4));
        ret = bt.reg_masks[1];
    } else if (sel == 6) {
        bt.frame = 1;
        bt.reg_masks[1] = (1U << BPF_REG_1) | (1U << BPF_REG_3);
        insns[0] = (struct bpf_insn){
            .code = BPF_JMP | BPF_CALL,
            .src_reg = BPF_PSEUDO_CALL,
        };
        BPF_PROVE(backtrack_insn(&env, 0, 1, NULL, &bt) == 0);
        BPF_PROVE(bt.frame == 0);
        BPF_PROVE(bt.reg_masks[0] ==
                  ((1U << BPF_REG_1) | (1U << BPF_REG_3)));
        BPF_PROVE(bt.reg_masks[1] == 0);
        ret = bt.reg_masks[0];
    } else {
        bt.frame = 0;
        bt.reg_masks[0] = 1U << BPF_REG_0;
        insns[0] = (struct bpf_insn){
            .code = BPF_JMP | BPF_EXIT,
        };
        insns[1] = (struct bpf_insn){
            .code = BPF_JMP | BPF_CALL,
            .src_reg = BPF_PSEUDO_CALL,
        };
        BPF_PROVE(backtrack_insn(&env, 0, 2, NULL, &bt) == 0);
        BPF_PROVE(bt.frame == 1);
        BPF_PROVE(bt.reg_masks[0] == 0);
        BPF_PROVE(bt.reg_masks[1] == (1U << BPF_REG_0));
        ret = bt.reg_masks[1];
    }

    return (int)(ret + (*vp & 1));
