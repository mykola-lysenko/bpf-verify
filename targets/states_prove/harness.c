    /* states proof harness: verifier-enforced invariants over dynamic ID,
     * scalar range, pointer identity, and reference parent state, plus
     * stack-arg equivalence coverage. Helper wrappers keep the checked logic
     * preserved in BPF bytecode instead of being optimized away by LLVM.
     */
    __u32 key = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &key);
    if (!vp) return 0;

    u32 old_id = (u32)((*vp & 0x0f) + 1);
    u32 cur_id = (u32)(((*vp >> 4) & 0x0f) + 32);
    u64 val64 = *vp & 0xff;
    int ret = 0;
    struct bpf_verifier_env *env = (struct bpf_verifier_env *)&__bpf_states_const_env;

    {
        struct bpf_idmap idmap = {};

        ret += states_idmap_proof_wrap(old_id, cur_id, &idmap);
        idmap.tmp_id_gen = 0;
        idmap.cnt = 0;
        ret += states_scalar_idmap_proof_wrap(old_id, cur_id, &idmap);
    }

    {
        struct bpf_idmap idmap = {};
        struct bpf_reg_state old_reg = {};
        struct bpf_reg_state cur_reg = {};

        old_reg.type = SCALAR_VALUE;
        old_reg.precise = true;
        old_reg.id = old_id;
        old_reg.var_off.value = 0;
        old_reg.var_off.mask = 0xff;
        old_reg.r64.base = 0;
        old_reg.r64.size = 0xff;
        old_reg.r32 = CNUM32_UNBOUNDED;

        cur_reg.type = SCALAR_VALUE;
        cur_reg.precise = true;
        cur_reg.id = cur_id;
        cur_reg.var_off.value = val64;
        cur_reg.var_off.mask = 0;
        cur_reg.r64.base = val64;
        cur_reg.r64.size = 0;
        cur_reg.r32 = CNUM32_UNBOUNDED;
        ret += states_regsafe_proof_wrap(env, &old_reg, &cur_reg, &idmap);

        cur_reg.id = cur_id | BPF_ADD_CONST32;
        idmap.tmp_id_gen = 0;
        idmap.cnt = 0;
        ret += states_regsafe_reject_wrap(env, &old_reg, &cur_reg, &idmap);
    }

    {
        struct bpf_idmap idmap = {};

        ret += states_pkt_regsafe_proof_wrap(env, old_id, cur_id, val64, &idmap);
    }

    {
        struct bpf_idmap idmap = {};

        ret += states_refsafe_proof_wrap(old_id, cur_id, &idmap);
        idmap.tmp_id_gen = 0;
        idmap.cnt = 0;
        ret += states_refsafe_reject_wrap(old_id, cur_id, &idmap);
        idmap.tmp_id_gen = 0;
        idmap.cnt = 0;
        ret += states_refsafe_ptr_proof_wrap(old_id, cur_id, &idmap);
    }

    {
        ret += states_stack_arg_safe_wrap(env, old_id, cur_id, val64);
        ret += states_looping_reject_wrap();
    }

    return ret + (int)val64;
