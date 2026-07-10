#pragma clang attribute pop
#pragma clang attribute pop
const struct bpf_verifier_env __bpf_states_const_env;
static struct bpf_reg_state __bpf_states_stack_old_args[2];
static struct bpf_reg_state __bpf_states_stack_cur_args[2];
static struct bpf_idmap __bpf_states_stack_idmap;
static const struct bpf_func_state __bpf_states_stack_old_one = {
    .out_stack_arg_cnt = 1,
    .stack_arg_regs = __bpf_states_stack_old_args,
};
static const struct bpf_func_state __bpf_states_stack_old_two = {
    .out_stack_arg_cnt = 2,
    .stack_arg_regs = __bpf_states_stack_old_args,
};
static const struct bpf_func_state __bpf_states_stack_cur_one = {
    .out_stack_arg_cnt = 1,
    .stack_arg_regs = __bpf_states_stack_cur_args,
};
static const struct bpf_func_state __bpf_states_stack_cur_two = {
    .out_stack_arg_cnt = 2,
    .stack_arg_regs = __bpf_states_stack_cur_args,
};

static __attribute__((__noinline__)) int
states_idmap_proof_wrap(u32 old_id, u32 cur_id, struct bpf_idmap *idmap)
{
    BPF_PROVE(check_ids(0, 0, idmap));
    BPF_PROVE(!check_ids(old_id, 0, idmap));
    BPF_PROVE(!check_ids(0, cur_id, idmap));
    BPF_PROVE(check_ids(old_id, cur_id, idmap));
    return (int)idmap->cnt;
}

static __attribute__((__noinline__)) int
states_scalar_idmap_proof_wrap(u32 old_id, u32 cur_id, struct bpf_idmap *idmap)
{
    BPF_PROVE(check_scalar_ids(0, cur_id, idmap));
    BPF_PROVE(check_scalar_ids(old_id, 0, idmap));
    return (int)idmap->cnt;
}

static __attribute__((__noinline__)) int
states_regsafe_proof_wrap(struct bpf_verifier_env *env,
                          struct bpf_reg_state *old_reg,
                          struct bpf_reg_state *cur_reg,
                          struct bpf_idmap *idmap)
{
    BPF_PROVE(regsafe(env, old_reg, cur_reg, idmap, NOT_EXACT));
    return (int)idmap->cnt;
}

static __attribute__((__noinline__)) int
states_regsafe_reject_wrap(struct bpf_verifier_env *env,
                           struct bpf_reg_state *old_reg,
                           struct bpf_reg_state *cur_reg,
                           struct bpf_idmap *idmap)
{
    BPF_PROVE(!regsafe(env, old_reg, cur_reg, idmap, NOT_EXACT));
    return (int)idmap->cnt;
}

static __attribute__((__noinline__)) int
states_pkt_regsafe_proof_wrap(struct bpf_verifier_env *env, u32 old_id,
                              u32 cur_id, u64 value,
                              struct bpf_idmap *idmap)
{
    struct bpf_reg_state old_reg = {};
    struct bpf_reg_state cur_reg = {};

    old_reg.type = PTR_TO_PACKET;
    old_reg.range = 8;
    old_reg.id = old_id;
    old_reg.var_off.value = 0;
    old_reg.var_off.mask = 0xff;
    old_reg.r64.base = 0;
    old_reg.r64.size = 0xff;
    old_reg.r32 = CNUM32_UNBOUNDED;

    cur_reg.type = PTR_TO_PACKET;
    cur_reg.range = 16;
    cur_reg.id = cur_id;
    cur_reg.var_off.value = value;
    cur_reg.var_off.mask = 0;
    cur_reg.r64.base = value;
    cur_reg.r64.size = 0;
    cur_reg.r32 = CNUM32_UNBOUNDED;

    BPF_PROVE(regsafe(env, &old_reg, &cur_reg, idmap, NOT_EXACT));
    return (int)idmap->cnt;
}

static __attribute__((__noinline__)) int
states_refsafe_proof_wrap(u32 old_id, u32 cur_id,
                          struct bpf_idmap *idmap)
{
    struct bpf_verifier_state old_st = {};
    struct bpf_verifier_state cur_st = {};

    old_st.acquired_refs = 1;
    cur_st.acquired_refs = 1;
    old_st.refs[0].type = REF_TYPE_IRQ;
    old_st.refs[0].id = old_id;
    cur_st.refs[0].type = REF_TYPE_IRQ;
    cur_st.refs[0].id = cur_id;

    BPF_PROVE(refsafe(&old_st, &cur_st, idmap));
    return (int)idmap->cnt;
}

static __attribute__((__noinline__)) int
states_refsafe_reject_wrap(u32 old_id, u32 cur_id,
                           struct bpf_idmap *idmap)
{
    struct bpf_verifier_state old_st = {};
    struct bpf_verifier_state cur_st = {};

    old_st.acquired_refs = 1;
    cur_st.acquired_refs = 1;
    old_st.refs[0].type = REF_TYPE_IRQ;
    old_st.refs[0].id = old_id;
    cur_st.refs[0].type = REF_TYPE_PTR;
    cur_st.refs[0].id = cur_id;

    BPF_PROVE(!refsafe(&old_st, &cur_st, idmap));
    return (int)idmap->cnt;
}

static __attribute__((__noinline__)) int
states_refsafe_ptr_proof_wrap(u32 old_id, u32 cur_id,
                              struct bpf_idmap *idmap)
{
    struct bpf_verifier_state old_st = {};
    struct bpf_verifier_state cur_st = {};

    old_st.acquired_refs = 1;
    cur_st.acquired_refs = 1;
    old_st.refs[0].type = REF_TYPE_PTR;
    old_st.refs[0].id = 0;
    old_st.refs[0].parent_id = old_id + 64;
    cur_st.refs[0].type = REF_TYPE_PTR;
    cur_st.refs[0].id = 0;
    cur_st.refs[0].parent_id = cur_id + 64;

    BPF_PROVE(refsafe(&old_st, &cur_st, idmap));
    return (int)idmap->cnt;
}

static __attribute__((__noinline__)) int
states_stack_arg_safe_wrap(struct bpf_verifier_env *env, u32 old_id,
                           u32 cur_id, u64 value)
{
    struct bpf_reg_state *old_args = __bpf_states_stack_old_args;
    struct bpf_reg_state *cur_args = __bpf_states_stack_cur_args;
    struct bpf_idmap *idmap = &__bpf_states_stack_idmap;

    value &= 0xff;
    idmap->tmp_id_gen = 0;
    idmap->cnt = 0;

    old_args[0] = (struct bpf_reg_state){
        .type = SCALAR_VALUE,
        .precise = true,
        .id = old_id,
        .var_off = { .value = 0, .mask = 0xff },
        .r64 = { .base = 0, .size = 0xff },
        .r32 = CNUM32_UNBOUNDED,
    };
    cur_args[0] = (struct bpf_reg_state){
        .type = SCALAR_VALUE,
        .precise = true,
        .id = cur_id,
        .var_off = { .value = value, .mask = 0 },
        .r64 = { .base = value, .size = 0 },
        .r32 = CNUM32_UNBOUNDED,
    };
    cur_args[1] = (struct bpf_reg_state){
        .type = SCALAR_VALUE,
        .precise = true,
        .id = cur_id + 1,
        .var_off = { .value = value, .mask = 0 },
        .r64 = { .base = value, .size = 0 },
        .r32 = CNUM32_UNBOUNDED,
    };

    BPF_ASSERT(stack_arg_safe(env,
                              (struct bpf_func_state *)&__bpf_states_stack_old_one,
                              (struct bpf_func_state *)&__bpf_states_stack_cur_two,
                              idmap, NOT_EXACT));

    idmap->tmp_id_gen = 0;
    idmap->cnt = 0;
    old_args[1] = old_args[0];
    BPF_ASSERT(!stack_arg_safe(env,
                               (struct bpf_func_state *)&__bpf_states_stack_old_two,
                               (struct bpf_func_state *)&__bpf_states_stack_cur_two,
                               idmap, NOT_EXACT));

    idmap->tmp_id_gen = 0;
    idmap->cnt = 0;
    BPF_ASSERT(!stack_arg_safe(env,
                               (struct bpf_func_state *)&__bpf_states_stack_old_two,
                               (struct bpf_func_state *)&__bpf_states_stack_cur_one,
                               idmap, NOT_EXACT));

    return 3;
}

static __attribute__((__noinline__)) int
states_looping_reject_wrap(void)
{
    struct bpf_verifier_state old_st = {};
    struct bpf_verifier_state cur_st = {};

    old_st.curframe = 0;
    cur_st.curframe = 1;
    BPF_PROVE(!states_maybe_looping(&old_st, &cur_st));
    return 1;
}
