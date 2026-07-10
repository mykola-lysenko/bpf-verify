#pragma clang attribute pop
static struct bpf_iarray __bpf_liveness_successors_succ;
static struct bpf_iarray __bpf_liveness_successors_jt;

static __attribute__((__noinline__)) int __bpf_liveness_successors_probe(void)
{
    struct bpf_verifier_env env = {};
    struct bpf_insn_aux_data aux = {};
    struct bpf_prog prog = {};
    struct bpf_insn insn = {};
    struct bpf_iarray *succ;
    int ret = 0;

    prog.insnsi = &insn;
    prog.len = 8;
    env.prog = &prog;
    env.insn_aux_data = &aux;
    env.succ = &__bpf_liveness_successors_succ;

    insn = (struct bpf_insn){
        .code = BPF_JMP | BPF_JEQ | BPF_K,
        .off = 2,
    };
    succ = bpf_insn_successors(&env, 0);
    if (!succ || succ->cnt != 2 || succ->items[0] != 1 || succ->items[1] != 3)
        return -1;
    ret += succ->cnt;

    aux.jt = NULL;
    insn = (struct bpf_insn){
        .code = BPF_JMP | BPF_JA,
        .off = 3,
    };
    succ = bpf_insn_successors(&env, 0);
    if (!succ || succ->cnt != 1 || succ->items[0] != 4)
        return -2;
    ret += succ->items[0];

    aux.jt = NULL;
    insn = (struct bpf_insn){
        .code = BPF_LD | BPF_IMM | BPF_DW,
    };
    succ = bpf_insn_successors(&env, 0);
    if (!succ || succ->cnt != 1 || succ->items[0] != 2)
        return -3;
    ret += succ->items[0];

    aux.jt = NULL;
    insn = (struct bpf_insn){
        .code = BPF_JMP | BPF_EXIT,
    };
    succ = bpf_insn_successors(&env, 0);
    if (!succ || succ->cnt != 0)
        return -4;

    __bpf_liveness_successors_jt.cnt = 2;
    __bpf_liveness_successors_jt.items[0] = 5;
    __bpf_liveness_successors_jt.items[1] = 7;
    aux.jt = &__bpf_liveness_successors_jt;
    insn = (struct bpf_insn){
        .code = BPF_JMP | BPF_JA,
        .off = 1,
    };
    succ = bpf_insn_successors(&env, 0);
    if (!succ || succ->cnt != 2 || succ->items[0] != 5 || succ->items[1] != 7)
        return -5;
    ret += succ->items[1];

    return ret;
}
