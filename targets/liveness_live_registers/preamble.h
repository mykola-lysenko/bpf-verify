#pragma clang attribute pop

static struct bpf_insn_aux_data __bpf_liveness_live_regs_aux[6];

static __attribute__((__noinline__)) int __bpf_liveness_live_registers_probe(void)
{
    struct bpf_verifier_env env = {};
    struct bpf_prog prog = {};
    struct bpf_insn insns[4];
    struct bpf_iarray succ = {};
    volatile struct insn_live_regs state[4] = {};
    struct bpf_insn_aux_data *aux = __bpf_liveness_live_regs_aux;
    bool changed;
    int i;

    insns[0] = (struct bpf_insn){
        .code = BPF_ALU64 | BPF_MOV | BPF_K,
        .dst_reg = BPF_REG_1,
        .imm = 0,
    };
    insns[1] = (struct bpf_insn){
        .code = BPF_ALU64 | BPF_MOV | BPF_X,
        .dst_reg = BPF_REG_2,
        .src_reg = BPF_REG_1,
    };
    insns[2] = (struct bpf_insn){
        .code = BPF_ALU64 | BPF_MOV | BPF_X,
        .dst_reg = BPF_REG_0,
        .src_reg = BPF_REG_2,
    };
    insns[3] = (struct bpf_insn){
        .code = BPF_JMP | BPF_EXIT,
    };

    aux[0].jt = NULL;
    aux[1].jt = NULL;
    aux[2].jt = NULL;
    aux[3].jt = NULL;
    aux[0].scc = 0;
    aux[1].scc = 0;
    aux[2].scc = 0;
    aux[3].scc = 0;
    aux[0].calls_callback = 0;
    aux[1].calls_callback = 0;
    aux[2].calls_callback = 0;
    aux[3].calls_callback = 0;

    prog.insnsi = insns;
    prog.len = 4;
    prog.aux = NULL;

    env.prog = &prog;
    env.insn_aux_data = aux;
    env.subprog_cnt = 0;
    env.subprog_topo_order[0] = 0;
    env.subprog_topo_order[1] = 0;
    env.subprog_info[0].start = 0;
    env.subprog_info[0].postorder_start = 0;
    env.subprog_info[0].is_global = false;
    env.subprog_info[1].start = 4;
    env.subprog_info[1].postorder_start = 4;
    env.subprog_info[1].is_global = false;
    env.cfg.insn_postorder = NULL;
    env.cfg.cur_postorder = 4;
    env.log.level = 0;
    env.succ = &succ;
    env.callsite_at_stack = NULL;

    state[0].def = BIT(BPF_REG_1);
    state[1].def = BIT(BPF_REG_2);
    state[1].use = BIT(BPF_REG_1);
    state[2].def = BIT(BPF_REG_0);
    state[2].use = BIT(BPF_REG_2);
    state[3].use = BIT(BPF_REG_0);

#define BPF_LIVENESS_STEP(insn_idx) do {                                              volatile struct insn_live_regs *live = &state[(insn_idx)];                    struct bpf_iarray *next = bpf_insn_successors(&env, (insn_idx));              u16 new_out = 0;                                                              u16 new_in;                                                                   int j;                                                                                                                                                       for (j = 0; j < 2; j++) {                                                         if (j >= next->cnt)                                                               break;                                                                    new_out |= state[next->items[j]].in;                                      }                                                                             new_in = (new_out & ~live->def) | live->use;                                  if (new_out != live->out || new_in != live->in) {                                 live->out = new_out;                                                          live->in = new_in;                                                            changed = true;                                                           }                                                                         } while (0)

    changed = true;
    for (i = 0; i < 4 && changed; i++) {
        changed = false;
        BPF_LIVENESS_STEP(3);
        BPF_LIVENESS_STEP(2);
        BPF_LIVENESS_STEP(1);
        BPF_LIVENESS_STEP(0);
    }
#undef BPF_LIVENESS_STEP

    aux[0].live_regs_before = state[0].in;
    aux[1].live_regs_before = state[1].in;
    aux[2].live_regs_before = state[2].in;
    aux[3].live_regs_before = state[3].in;

    if (state[0].in != 0)
        return -1;
    if (state[1].in != BIT(BPF_REG_1))
        return -2;
    if (state[2].in != BIT(BPF_REG_2))
        return -3;
    if (state[3].in != BIT(BPF_REG_0))
        return -4;

    {
        struct bpf_insn branch_insns[6];
        volatile struct insn_live_regs branch_state[6] = {};

        branch_insns[0] = (struct bpf_insn){
            .code = BPF_JMP | BPF_JEQ | BPF_K,
            .dst_reg = BPF_REG_1,
            .off = 2,
        };
        branch_insns[1] = (struct bpf_insn){
            .code = BPF_ALU64 | BPF_MOV | BPF_X,
            .dst_reg = BPF_REG_2,
            .src_reg = BPF_REG_3,
        };
        branch_insns[2] = (struct bpf_insn){
            .code = BPF_JMP | BPF_JA,
            .off = 1,
        };
        branch_insns[3] = (struct bpf_insn){
            .code = BPF_ALU64 | BPF_MOV | BPF_X,
            .dst_reg = BPF_REG_2,
            .src_reg = BPF_REG_4,
        };
        branch_insns[4] = (struct bpf_insn){
            .code = BPF_ALU64 | BPF_MOV | BPF_X,
            .dst_reg = BPF_REG_0,
            .src_reg = BPF_REG_2,
        };
        branch_insns[5] = (struct bpf_insn){
            .code = BPF_JMP | BPF_EXIT,
        };

        aux[0].jt = NULL;
        aux[1].jt = NULL;
        aux[2].jt = NULL;
        aux[3].jt = NULL;
        aux[4].jt = NULL;
        aux[5].jt = NULL;
        aux[4].scc = 0;
        aux[5].scc = 0;
        aux[4].calls_callback = 0;
        aux[5].calls_callback = 0;

        prog.insnsi = branch_insns;
        prog.len = 6;

        branch_state[0].use = BIT(BPF_REG_1);
        branch_state[1].def = BIT(BPF_REG_2);
        branch_state[1].use = BIT(BPF_REG_3);
        branch_state[2].use = 0;
        branch_state[3].def = BIT(BPF_REG_2);
        branch_state[3].use = BIT(BPF_REG_4);
        branch_state[4].def = BIT(BPF_REG_0);
        branch_state[4].use = BIT(BPF_REG_2);
        branch_state[5].use = BIT(BPF_REG_0);

#define BPF_LIVENESS_BRANCH_STEP(insn_idx) do {                                       volatile struct insn_live_regs *live = &branch_state[(insn_idx)];             struct bpf_iarray *next = bpf_insn_successors(&env, (insn_idx));              u16 new_out = 0;                                                              u16 new_in;                                                                   int j;                                                                                                                                                       for (j = 0; j < 2; j++) {                                                         if (j >= next->cnt)                                                               break;                                                                    new_out |= branch_state[next->items[j]].in;                               }                                                                             new_in = (new_out & ~live->def) | live->use;                                  if (new_out != live->out || new_in != live->in) {                                 live->out = new_out;                                                          live->in = new_in;                                                            changed = true;                                                           }                                                                         } while (0)

        changed = true;
        for (i = 0; i < 6 && changed; i++) {
            changed = false;
            BPF_LIVENESS_BRANCH_STEP(5);
            BPF_LIVENESS_BRANCH_STEP(4);
            BPF_LIVENESS_BRANCH_STEP(3);
            BPF_LIVENESS_BRANCH_STEP(2);
            BPF_LIVENESS_BRANCH_STEP(1);
            BPF_LIVENESS_BRANCH_STEP(0);
        }
#undef BPF_LIVENESS_BRANCH_STEP

        aux[0].live_regs_before = branch_state[0].in;
        aux[1].live_regs_before = branch_state[1].in;
        aux[2].live_regs_before = branch_state[2].in;
        aux[3].live_regs_before = branch_state[3].in;
        aux[4].live_regs_before = branch_state[4].in;
        aux[5].live_regs_before = branch_state[5].in;

        if (branch_state[0].in != (BIT(BPF_REG_1) | BIT(BPF_REG_3) | BIT(BPF_REG_4)))
            return -5;
        if (branch_state[1].in != BIT(BPF_REG_3))
            return -6;
        if (branch_state[2].in != BIT(BPF_REG_2))
            return -7;
        if (branch_state[3].in != BIT(BPF_REG_4))
            return -8;
        if (branch_state[4].in != BIT(BPF_REG_2))
            return -9;
        if (branch_state[5].in != BIT(BPF_REG_0))
            return -10;
        if (branch_state[0].out != (BIT(BPF_REG_3) | BIT(BPF_REG_4)))
            return -11;
    }

    return 31;
}
