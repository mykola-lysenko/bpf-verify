    /* cfg: verifier control-flow graph edge helpers.
     * The full bpf_check_cfg() path can reach indirect map-ops calls while
     * handling gotox jump tables, and postorder/SCC walks reload indexes from
     * allocator-backed memory in a way the BPF verifier cannot bound. Cover
     * the core DFS edge transitions and abnormal-return jump table creation
     * directly.
     */
    static struct bpf_insn insns[4];
    static struct bpf_insn_aux_data aux[4];
    struct bpf_prog_aux prog_aux = {};
    struct bpf_prog prog = {};
    struct bpf_verifier_env env = {};
    int state[4] = {};
    int stack[4] = {};
    int call_state[4] = {};
    int call_stack[4] = {};

    insns[0] = (struct bpf_insn){
        .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0,
    };
    insns[1] = (struct bpf_insn){
        .code = BPF_JMP | BPF_JEQ | BPF_K, .dst_reg = BPF_REG_0, .off = 1, .imm = 0,
    };
    insns[2] = (struct bpf_insn){
        .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 1,
    };
    insns[3] = (struct bpf_insn){ .code = BPF_JMP | BPF_EXIT };

    prog.insnsi = insns;
    prog.len = 4;
    prog.aux = &prog_aux;
    env.prog = &prog;
    env.insn_aux_data = aux;
    env.subprog_cnt = 1;
    env.subprog_info[0].start = 0;
    env.subprog_info[0].exit_idx = 3;
    env.subprog_info[1].start = 4;
    env.exception_callback_subprog = 0;

    env.cfg.insn_state = state;
    env.cfg.insn_stack = stack;
    env.cfg.cur_stack = 0;
    state[0] = DISCOVERED;
    BPF_ASSERT(push_insn(0, 1, FALLTHROUGH, &env) == KEEP_EXPLORING);
    BPF_ASSERT(state[0] == (DISCOVERED | FALLTHROUGH));
    BPF_ASSERT(state[1] == DISCOVERED);
    BPF_ASSERT(stack[0] == 1);
    BPF_ASSERT(env.cfg.cur_stack == 1);

    state[2] = EXPLORED;
    BPF_ASSERT(push_insn(1, 2, BRANCH, &env) == DONE_EXPLORING);
    BPF_ASSERT(state[1] == (DISCOVERED | BRANCH));
    BPF_ASSERT(aux[2].prune_point);
    BPF_ASSERT(aux[2].jmp_point);

    state[3] = DISCOVERED;
    BPF_ASSERT(push_insn(2, 3, BRANCH, &env) == -EINVAL);

    insns[0] = (struct bpf_insn){ .code = BPF_JMP | BPF_CALL };
    env.cfg.insn_state = call_state;
    env.cfg.insn_stack = call_stack;
    env.cfg.cur_stack = 0;
    call_state[0] = DISCOVERED;
    BPF_ASSERT(visit_func_call_insn(0, insns, &env, false) == KEEP_EXPLORING);
    BPF_ASSERT(call_state[1] == DISCOVERED);
    BPF_ASSERT(call_stack[0] == 1);
    BPF_ASSERT(aux[1].prune_point);
    BPF_ASSERT(aux[1].jmp_point);

    BPF_ASSERT(visit_abnormal_return_insn(&env, 2) == 0);
    BPF_ASSERT(aux[2].jt != 0);
    BPF_ASSERT(prog_aux.changes_pkt_data == false);
    BPF_ASSERT(prog_aux.might_sleep == false);

    return (int)(aux[1].jmp_point + aux[2].prune_point);
