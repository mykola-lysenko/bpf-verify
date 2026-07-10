    /* fixups_prove: verifier-enforced instruction classifier invariants. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    __u64 choice = input ? *input : 0;
    struct bpf_insn insn = {};
    u8 code;
    int def;
    bool ok;
    int acc = 0;

    code = BPF_JMP | BPF_JEQ | BPF_K;
    BPF_KEEP_SCALAR(code);
    ok = bpf_insn_is_cond_jump(code);
    BPF_KEEP_SCALAR(ok);
    BPF_PROVE(ok);

    code = BPF_JMP | BPF_CALL | BPF_K;
    BPF_KEEP_SCALAR(code);
    ok = bpf_insn_is_cond_jump(code);
    BPF_KEEP_SCALAR(ok);
    BPF_PROVE(!ok);

    code = BPF_JMP32 | BPF_JEQ | BPF_K;
    BPF_KEEP_SCALAR(code);
    ok = bpf_insn_is_cond_jump(code);
    BPF_KEEP_SCALAR(ok);
    BPF_PROVE(ok);

    code = BPF_JMP32 | BPF_JA;
    BPF_KEEP_SCALAR(code);
    ok = bpf_insn_is_cond_jump(code);
    BPF_KEEP_SCALAR(ok);
    BPF_PROVE(!ok);

    BPF_PROVE(!bpf_insn_is_cond_jump(BPF_ALU64 | BPF_MOV | BPF_X));
    BPF_PROVE(!bpf_insn_is_cond_jump(BPF_JMP | BPF_EXIT));
    BPF_PROVE(!bpf_insn_is_cond_jump(BPF_JMP | BPF_JA));
    BPF_PROVE(bpf_insn_is_cond_jump(BPF_JMP | BPF_JCOND));

    insn = BPF_ALU32_REG(BPF_MOV, BPF_REG_2, BPF_REG_1);
    BPF_KEEP_SCALAR(insn.code);
    def = insn_def_regno(&insn);
    BPF_KEEP_SCALAR(def);
    ok = insn_has_def32(&insn);
    BPF_KEEP_SCALAR(ok);
    BPF_PROVE(def == BPF_REG_2);
    BPF_PROVE(ok);

    insn = BPF_ALU64_REG(BPF_MOV, BPF_REG_3, BPF_REG_1);
    BPF_KEEP_SCALAR(insn.code);
    def = insn_def_regno(&insn);
    BPF_KEEP_SCALAR(def);
    ok = insn_has_def32(&insn);
    BPF_KEEP_SCALAR(ok);
    BPF_PROVE(def == BPF_REG_3);
    BPF_PROVE(!ok);

    insn = BPF_STX_ATOMIC(BPF_W, BPF_REG_1, BPF_REG_2, 0,
                          BPF_CMPXCHG);
    BPF_KEEP_SCALAR(insn.code);
    BPF_KEEP_SCALAR(insn.imm);
    def = insn_def_regno(&insn);
    BPF_KEEP_SCALAR(def);
    ok = insn_has_def32(&insn);
    BPF_KEEP_SCALAR(ok);
    BPF_PROVE(def == BPF_REG_0);
    BPF_PROVE(ok);

    insn = BPF_STX_ATOMIC(BPF_DW, BPF_REG_1, BPF_REG_2, 0,
                          BPF_CMPXCHG);
    BPF_KEEP_SCALAR(insn.code);
    BPF_KEEP_SCALAR(insn.imm);
    def = insn_def_regno(&insn);
    BPF_KEEP_SCALAR(def);
    ok = insn_has_def32(&insn);
    BPF_KEEP_SCALAR(ok);
    BPF_PROVE(def == BPF_REG_0);
    BPF_PROVE(!ok);

    insn = BPF_STX_ATOMIC(BPF_W, BPF_REG_1, BPF_REG_2, 0,
                          BPF_FETCH | BPF_ADD);
    BPF_KEEP_SCALAR(insn.code);
    BPF_KEEP_SCALAR(insn.imm);
    def = insn_def_regno(&insn);
    BPF_KEEP_SCALAR(def);
    ok = insn_has_def32(&insn);
    BPF_KEEP_SCALAR(ok);
    BPF_PROVE(def == BPF_REG_2);
    BPF_PROVE(ok);

    insn = BPF_STX_ATOMIC(BPF_DW, BPF_REG_1, BPF_REG_2, 0,
                          BPF_FETCH | BPF_ADD);
    BPF_KEEP_SCALAR(insn.code);
    BPF_KEEP_SCALAR(insn.imm);
    def = insn_def_regno(&insn);
    BPF_KEEP_SCALAR(def);
    ok = insn_has_def32(&insn);
    BPF_KEEP_SCALAR(ok);
    BPF_PROVE(def == BPF_REG_2);
    BPF_PROVE(!ok);

    insn = BPF_STX_ATOMIC(BPF_W, BPF_REG_1, BPF_REG_2, 0, BPF_ADD);
    BPF_PROVE(insn_def_regno(&insn) == -1);
    BPF_PROVE(!insn_has_def32(&insn));
    insn = BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 1);
    BPF_PROVE(insn_def_regno(&insn) == -1);
    BPF_PROVE(!insn_has_def32(&insn));
    insn = BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1, 0);
    BPF_PROVE(insn_def_regno(&insn) == BPF_REG_3);
    BPF_PROVE(insn_has_def32(&insn));
    insn = BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_1, 0);
    BPF_PROVE(insn_def_regno(&insn) == BPF_REG_3);
    BPF_PROVE(!insn_has_def32(&insn));

    acc += def;
    acc += ok;
    return (int)choice + acc;
