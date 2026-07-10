    /* const_fold: verifier pass for known constant register values and
     * conditional branch pruning. The full dataflow driver uses dynamic stack
     * indexing that BPF rejects, so this harness covers the transfer function
     * and the branch rewrite directly.
     */
    struct bpf_insn insns[4];
    static struct bpf_insn_aux_data aux[4];
    static struct const_arg_info ci[MAX_BPF_REG];
    struct bpf_prog prog;
    struct bpf_verifier_env env;

    insns[0] = (struct bpf_insn){
        .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_1, .imm = 42,
    };
    insns[1] = (struct bpf_insn){
        .code = BPF_JMP | BPF_JEQ | BPF_K, .dst_reg = BPF_REG_1, .off = 1, .imm = 42,
    };
    insns[2] = (struct bpf_insn){
        .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0,
    };
    insns[3] = (struct bpf_insn){ .code = BPF_JMP | BPF_EXIT };

    prog.insnsi = insns;
    prog.len = 4;
    env.prog = &prog;
    env.insn_aux_data = aux;
    env.cfg.insn_postorder = NULL;

    const_reg_xfer(&env, ci, &insns[0], insns, 0);
    BPF_ASSERT(ci[BPF_REG_1].state == CONST_ARG_CONST);
    BPF_ASSERT(ci[BPF_REG_1].val == 42);

    aux[1].const_reg_mask = BIT(BPF_REG_1);
    aux[1].const_reg_vals[BPF_REG_1] = 42;
    BPF_ASSERT(aux[1].const_reg_mask & BIT(BPF_REG_1));
    BPF_ASSERT(aux[1].const_reg_vals[BPF_REG_1] == 42);

    BPF_ASSERT(bpf_prune_dead_branches(&env) == 0);
    BPF_ASSERT(insns[1].code == (BPF_JMP | BPF_JA));
    BPF_ASSERT(insns[1].off == 1);

    return insns[1].off;
