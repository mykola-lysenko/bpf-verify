#pragma clang attribute pop
#pragma clang attribute pop
const struct bpf_verifier_env __bpf_states_const_env;
const struct bpf_func_state __bpf_states_old_func = {
    .callsite = 0,
    .allocated_stack = 0,
    .regs = {
        [BPF_REG_1] = {
            .type = SCALAR_VALUE,
            .precise = true,
            .id = 7,
            .var_off = { .value = 0, .mask = 0xff },
            .r64 = { .base = 0, .size = 100 },
            .r32 = { .base = 0, .size = 100 },
        },
    },
};
const struct bpf_func_state __bpf_states_bad_func = {
    .callsite = 0,
    .allocated_stack = 0,
    .regs = {
        [BPF_REG_1] = {
            .type = PTR_TO_STACK,
        },
    },
};
struct bpf_reg_state __bpf_states_old_reg;
struct bpf_reg_state __bpf_states_cur_reg;
