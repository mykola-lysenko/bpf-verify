    /* states: verifier state-equivalence and pruning helpers. */
    struct bpf_idmap idmap_obj = {};
    struct bpf_idmap *idmap = &idmap_obj;
    struct bpf_verifier_state old_state_obj = {};
    struct bpf_verifier_state cur_state_obj = {};
    struct bpf_reg_state *old_reg = &__bpf_states_old_reg;
    struct bpf_reg_state *cur_reg = &__bpf_states_cur_reg;
    struct bpf_verifier_env *env = (struct bpf_verifier_env *)&__bpf_states_const_env;
    struct bpf_verifier_state *old_st = &old_state_obj;
    struct bpf_verifier_state *cur_st = &cur_state_obj;
    struct bpf_func_state *old_fn = (struct bpf_func_state *)&__bpf_states_old_func;

    idmap->tmp_id_gen = 0;
    idmap->cnt = 0;
    BPF_ASSERT(check_ids(0, 0, idmap));
    BPF_ASSERT(!check_ids(1, 0, idmap));
    BPF_ASSERT(check_ids(1, 5, idmap));
    BPF_ASSERT(check_ids(1, 5, idmap));
    BPF_ASSERT(!check_ids(1, 6, idmap));
    BPF_ASSERT(!check_ids(2, 5, idmap));

    idmap->tmp_id_gen = 0;
    idmap->cnt = 0;
    BPF_ASSERT(check_scalar_ids(3, 0, idmap));
    BPF_ASSERT(!check_scalar_ids(3, 0, idmap));

    idmap->tmp_id_gen = 0;
    idmap->cnt = 0;
    BPF_ASSERT(check_scalar_ids(4, 40, idmap));
    BPF_ASSERT(!check_scalar_ids(4 | BPF_ADD_CONST64,
                                 41 | BPF_ADD_CONST64, idmap));

    memset(old_reg, 0, sizeof(*old_reg));
    memset(cur_reg, 0, sizeof(*cur_reg));
    old_reg->type = SCALAR_VALUE;
    old_reg->precise = true;
    old_reg->id = 7;
    old_reg->var_off.value = 0;
    old_reg->var_off.mask = 0xff;
    old_reg->r64.base = 0;
    old_reg->r64.size = 100;
    old_reg->r32.base = 0;
    old_reg->r32.size = 100;
    cur_reg->type = SCALAR_VALUE;
    cur_reg->precise = true;
    cur_reg->id = 8;
    cur_reg->var_off.value = 16;
    cur_reg->var_off.mask = 0;
    cur_reg->r64.base = 16;
    cur_reg->r64.size = 16;
    cur_reg->r32.base = 16;
    cur_reg->r32.size = 16;
    idmap->tmp_id_gen = 0;
    idmap->cnt = 0;
    BPF_ASSERT(regsafe(env, old_reg, cur_reg, idmap, NOT_EXACT));

    old_reg->id = 7 | BPF_ADD_CONST64;
    cur_reg->id = 8 | BPF_ADD_CONST32;
    idmap->tmp_id_gen = 0;
    idmap->cnt = 0;
    BPF_ASSERT(!regsafe(env, old_reg, cur_reg, idmap, NOT_EXACT));
    old_reg->id = 7;
    cur_reg->id = 8;

    memset(old_st, 0, sizeof(*old_st));
    memset(cur_st, 0, sizeof(*cur_st));
    old_st->acquired_refs = 1;
    cur_st->acquired_refs = 1;
    old_st->refs[0].type = REF_TYPE_PTR;
    old_st->refs[0].id = 10;
    old_st->refs[0].parent_id = 20;
    cur_st->refs[0].type = REF_TYPE_PTR;
    cur_st->refs[0].id = 30;
    cur_st->refs[0].parent_id = 40;
    idmap->tmp_id_gen = 0;
    idmap->cnt = 0;
    BPF_ASSERT(refsafe(old_st, cur_st, idmap));
    cur_st->refs[0].type = REF_TYPE_IRQ;
    idmap->tmp_id_gen = 0;
    idmap->cnt = 0;
    BPF_ASSERT(!refsafe(old_st, cur_st, idmap));

    memset(old_st, 0, sizeof(*old_st));
    memset(cur_st, 0, sizeof(*cur_st));
    old_st->frame[0] = old_fn;
    cur_st->frame[0] = old_fn;
    old_st->curframe = 0;
    cur_st->curframe = 0;
    BPF_ASSERT(states_maybe_looping(old_st, cur_st));
    cur_st->frame[0] = (struct bpf_func_state *)&__bpf_states_bad_func;
    BPF_ASSERT(!states_maybe_looping(old_st, cur_st));

    return (int)(old_reg->id + cur_reg->id);
