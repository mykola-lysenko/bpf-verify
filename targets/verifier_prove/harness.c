    /* verifier_prove: verifier-local predicate and helper-prototype invariants. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    __u64 choice = input ? *input : 0;
    struct bpf_verifier_env env = {};
    struct bpf_map sockmap = { .map_type = BPF_MAP_TYPE_SOCKMAP };
    struct bpf_map sockhash = { .map_type = BPF_MAP_TYPE_SOCKHASH };
    struct bpf_map hash = { .map_type = BPF_MAP_TYPE_HASH };
    struct bpf_func_state state = { .allocated_stack = 32 };
    struct bpf_reg_state reg = {};
    struct bpf_func_proto fn = {};
    struct bpf_call_arg_meta meta = {};
    argno_t a;
    u32 btf_id = 1;
    u64 val;
    int ret;
    int acc = 0;

    a = argno_from_reg(BPF_REG_3);
    BPF_KEEP_SCALAR(a.argno);
    ret = reg_from_argno(a);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == BPF_REG_3);
    ret = arg_from_argno(a);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -1);

    a = argno_from_arg(2);
    BPF_KEEP_SCALAR(a.argno);
    ret = reg_from_argno(a);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == BPF_REG_2);
    ret = arg_idx_from_argno(a);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 1);

    a = argno_from_arg(MAX_BPF_FUNC_REG_ARGS + 1);
    BPF_KEEP_SCALAR(a.argno);
    ret = reg_from_argno(a);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -1);

    reg.type = SCALAR_VALUE;
    BPF_KEEP_SCALAR(reg.type);
    BPF_PROVE(!reg_not_null(&env, &reg));
    reg.type = PTR_TO_MAP_VALUE;
    BPF_KEEP_SCALAR(reg.type);
    BPF_PROVE(reg_not_null(&env, &reg));
    reg.type = PTR_TO_MAP_VALUE_OR_NULL;
    BPF_KEEP_SCALAR(reg.type);
    BPF_PROVE(!reg_not_null(&env, &reg));
    reg.type = PTR_TO_MEM | PTR_UNTRUSTED;
    BPF_KEEP_SCALAR(reg.type);
    BPF_PROVE(!reg_not_null(&env, &reg));
    reg.type = PTR_TO_MEM;
    BPF_KEEP_SCALAR(reg.type);
    BPF_PROVE(reg_not_null(&env, &reg));
    reg.type = PTR_TO_BTF_ID | PTR_TRUSTED;
    reg.id = 0;
    BPF_KEEP_SCALAR(reg.type);
    BPF_PROVE(reg_not_null(&env, &reg));
    reg.type = PTR_TO_BTF_ID | PTR_UNTRUSTED;
    BPF_KEEP_SCALAR(reg.type);
    BPF_PROVE(!reg_not_null(&env, &reg));
    reg.type = PTR_TO_BTF_ID;
    reg.id = 123;
    BPF_KEEP_SCALAR(reg.id);
    BPF_PROVE(reg_not_null(&env, &reg));
    reg.id = 0;

    BPF_PROVE(type_is_rdonly_mem(PTR_TO_MEM | MEM_RDONLY));
    BPF_PROVE(!type_is_rdonly_mem(PTR_TO_MEM));

    BPF_KEEP_SCALAR(sockmap.map_type);
    BPF_KEEP_SCALAR(sockhash.map_type);
    BPF_KEEP_SCALAR(hash.map_type);
    BPF_PROVE(is_acquire_function(BPF_FUNC_sk_lookup_tcp, NULL));
    BPF_PROVE(is_acquire_function(BPF_FUNC_ringbuf_reserve, NULL));
    BPF_PROVE(is_acquire_function(BPF_FUNC_kptr_xchg, NULL));
    BPF_PROVE(is_acquire_function(BPF_FUNC_map_lookup_elem, &sockmap));
    BPF_PROVE(is_acquire_function(BPF_FUNC_map_lookup_elem, &sockhash));
    BPF_PROVE(!is_acquire_function(BPF_FUNC_map_lookup_elem, &hash));
    BPF_PROVE(!is_acquire_function(BPF_FUNC_loop, NULL));

    BPF_PROVE(is_ptr_cast_function(BPF_FUNC_tcp_sock));
    BPF_PROVE(is_ptr_cast_function(BPF_FUNC_skc_to_tcp_request_sock));
    BPF_PROVE(!is_ptr_cast_function(BPF_FUNC_map_lookup_elem));
    BPF_PROVE(is_sync_callback_calling_function(BPF_FUNC_for_each_map_elem));
    BPF_PROVE(is_sync_callback_calling_function(BPF_FUNC_loop));
    BPF_PROVE(!is_sync_callback_calling_function(BPF_FUNC_timer_set_callback));
    BPF_PROVE(is_async_callback_calling_function(BPF_FUNC_timer_set_callback));
    BPF_PROVE(is_callback_calling_function(BPF_FUNC_user_ringbuf_drain));
    BPF_PROVE(is_callback_calling_function(BPF_FUNC_timer_set_callback));
    BPF_PROVE(!is_callback_calling_function(BPF_FUNC_map_lookup_elem));

    BPF_KEEP_SCALAR(state.allocated_stack);
    BPF_PROVE(is_spi_bounds_valid(&state, 3, 2));
    BPF_PROVE(!is_spi_bounds_valid(&state, 0, 2));
    BPF_PROVE(!is_spi_bounds_valid(&state, 4, 1));

    BPF_PROVE(arg_to_dynptr_type(ARG_PTR_TO_DYNPTR | DYNPTR_TYPE_LOCAL) ==
              BPF_DYNPTR_TYPE_LOCAL);
    BPF_PROVE(arg_to_dynptr_type(ARG_PTR_TO_DYNPTR | DYNPTR_TYPE_RINGBUF) ==
              BPF_DYNPTR_TYPE_RINGBUF);
    BPF_PROVE(arg_to_dynptr_type(ARG_PTR_TO_DYNPTR | DYNPTR_TYPE_FILE) ==
              BPF_DYNPTR_TYPE_FILE);
    BPF_PROVE(arg_to_dynptr_type(ARG_PTR_TO_DYNPTR) ==
              BPF_DYNPTR_TYPE_INVALID);
    BPF_PROVE(get_dynptr_type_flag(BPF_DYNPTR_TYPE_SKB) == DYNPTR_TYPE_SKB);
    BPF_PROVE(get_dynptr_type_flag(BPF_DYNPTR_TYPE_XDP) == DYNPTR_TYPE_XDP);
    BPF_PROVE(get_dynptr_type_flag(BPF_DYNPTR_TYPE_INVALID) == 0);
    BPF_PROVE(dynptr_type_referenced(BPF_DYNPTR_TYPE_RINGBUF));
    BPF_PROVE(dynptr_type_referenced(BPF_DYNPTR_TYPE_FILE));
    BPF_PROVE(!dynptr_type_referenced(BPF_DYNPTR_TYPE_LOCAL));

    BPF_PROVE(error_recoverable_with_nospec(-EPERM));
    BPF_PROVE(error_recoverable_with_nospec(-EACCES));
    BPF_PROVE(error_recoverable_with_nospec(-EINVAL));
    BPF_PROVE(!error_recoverable_with_nospec(-ENOMEM));

    reg.type = PTR_TO_PACKET;
    reg.id = 0;
    reg.var_off = tnum_const(0);
    BPF_PROVE(reg_is_pkt_pointer(&reg));
    BPF_PROVE(reg_is_pkt_pointer_any(&reg));
    BPF_PROVE(reg_is_init_pkt_pointer(&reg, PTR_TO_PACKET));
    reg.var_off.mask = 1;
    BPF_KEEP_SCALAR(reg.var_off.mask);
    BPF_PROVE(!reg_is_init_pkt_pointer(&reg, PTR_TO_PACKET));
    reg.type = PTR_TO_PACKET_END;
    reg.var_off = tnum_const(0);
    BPF_PROVE(!reg_is_pkt_pointer(&reg));
    BPF_PROVE(reg_is_pkt_pointer_any(&reg));
    reg.type = PTR_TO_MEM | DYNPTR_TYPE_SKB;
    BPF_KEEP_SCALAR(reg.type);
    BPF_PROVE(reg_is_dynptr_slice_pkt(&reg));
    reg.type = PTR_TO_MEM;
    BPF_KEEP_SCALAR(reg.type);
    BPF_PROVE(!reg_is_dynptr_slice_pkt(&reg));

    BPF_PROVE(is_spillable_regtype(PTR_TO_MAP_VALUE));
    BPF_PROVE(is_spillable_regtype(PTR_TO_BTF_ID | PTR_TRUSTED));
    BPF_PROVE(is_spillable_regtype(PTR_TO_ARENA));
    BPF_PROVE(!is_spillable_regtype(SCALAR_VALUE));
    BPF_PROVE(!is_spillable_regtype(NOT_INIT));

    reg.type = SCALAR_VALUE;
    reg.var_off = tnum_const(0x100000005ULL);
    BPF_KEEP_SCALAR(reg.type);
    BPF_PROVE(is_reg_const(&reg, false));
    BPF_PROVE(is_reg_const(&reg, true));
    val = reg_const_value(&reg, false);
    BPF_KEEP_SCALAR(val);
    BPF_PROVE(val == 0x100000005ULL);
    val = reg_const_value(&reg, true);
    BPF_KEEP_SCALAR(val);
    BPF_PROVE(val == 5);
    reg.var_off.mask = 0x100000000ULL;
    BPF_KEEP_SCALAR(reg.var_off.mask);
    BPF_PROVE(!is_reg_const(&reg, false));
    BPF_PROVE(is_reg_const(&reg, true));
    reg.type = PTR_TO_STACK;
    BPF_KEEP_SCALAR(reg.type);
    BPF_PROVE(!is_reg_const(&reg, true));
    BPF_PROVE(__is_pointer_value(false, &reg));
    BPF_PROVE(!__is_pointer_value(true, &reg));
    reg.type = SCALAR_VALUE;
    BPF_PROVE(!__is_pointer_value(false, &reg));

    BPF_PROVE(arg_type_is_mem_size(ARG_CONST_SIZE));
    BPF_PROVE(arg_type_is_mem_size(ARG_CONST_SIZE_OR_ZERO));
    BPF_PROVE(!arg_type_is_mem_size(ARG_PTR_TO_MEM));
    BPF_PROVE(arg_type_is_raw_mem(ARG_PTR_TO_UNINIT_MEM));
    BPF_PROVE(!arg_type_is_raw_mem(ARG_PTR_TO_MEM | MEM_WRITE));
    BPF_PROVE(arg_type_is_release(ARG_PTR_TO_SOCKET | OBJ_RELEASE));
    BPF_PROVE(!arg_type_is_release(ARG_PTR_TO_SOCKET));
    BPF_PROVE(arg_type_is_dynptr(ARG_PTR_TO_DYNPTR | OBJ_RELEASE));
    BPF_PROVE(!arg_type_is_dynptr(ARG_PTR_TO_MEM));

    fn.arg1_type = ARG_PTR_TO_MEM | MEM_WRITE;
    fn.arg2_type = ARG_CONST_SIZE;
    fn.arg3_type = ARG_DONTCARE;
    fn.arg4_type = ARG_DONTCARE;
    fn.arg5_type = ARG_DONTCARE;
    fn.arg1_btf_id = NULL;
    fn.arg2_btf_id = NULL;
    fn.arg3_btf_id = NULL;
    fn.arg4_btf_id = NULL;
    fn.arg5_btf_id = NULL;
    meta.release_regno = 0;
    BPF_KEEP_SCALAR(fn.arg1_type);
    BPF_KEEP_SCALAR(fn.arg2_type);
    ret = check_func_proto(&fn, &meta);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    BPF_PROVE(meta.release_regno == 0);

    fn.arg1_type = ARG_PTR_TO_UNINIT_MEM;
    fn.arg2_type = ARG_CONST_SIZE;
    fn.arg3_type = ARG_PTR_TO_UNINIT_MEM;
    fn.arg4_type = ARG_CONST_SIZE;
    fn.arg5_type = ARG_DONTCARE;
    meta.release_regno = 0;
    BPF_KEEP_SCALAR(fn.arg1_type);
    BPF_KEEP_SCALAR(fn.arg3_type);
    ret = check_func_proto(&fn, &meta);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    fn.arg1_type = ARG_CONST_SIZE;
    fn.arg2_type = ARG_DONTCARE;
    fn.arg3_type = ARG_DONTCARE;
    fn.arg4_type = ARG_DONTCARE;
    fn.arg5_type = ARG_DONTCARE;
    meta.release_regno = 0;
    BPF_KEEP_SCALAR(fn.arg1_type);
    ret = check_func_proto(&fn, &meta);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    fn.arg1_type = ARG_PTR_TO_MEM;
    fn.arg2_type = ARG_DONTCARE;
    fn.arg3_type = ARG_DONTCARE;
    fn.arg4_type = ARG_DONTCARE;
    fn.arg5_type = ARG_DONTCARE;
    meta.release_regno = 0;
    BPF_KEEP_SCALAR(fn.arg1_type);
    ret = check_func_proto(&fn, &meta);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    fn.arg1_type = ARG_PTR_TO_SOCKET | OBJ_RELEASE;
    fn.arg2_type = ARG_DONTCARE;
    fn.arg3_type = ARG_DONTCARE;
    fn.arg4_type = ARG_DONTCARE;
    fn.arg5_type = ARG_DONTCARE;
    meta.release_regno = 0;
    BPF_KEEP_SCALAR(fn.arg1_type);
    ret = check_func_proto(&fn, &meta);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    BPF_PROVE(meta.release_regno == 1);

    fn.arg1_type = ARG_PTR_TO_SOCKET | OBJ_RELEASE;
    fn.arg2_type = ARG_PTR_TO_SOCKET | OBJ_RELEASE;
    fn.arg3_type = ARG_DONTCARE;
    fn.arg4_type = ARG_DONTCARE;
    fn.arg5_type = ARG_DONTCARE;
    meta.release_regno = 0;
    BPF_KEEP_SCALAR(fn.arg1_type);
    BPF_KEEP_SCALAR(fn.arg2_type);
    ret = check_func_proto(&fn, &meta);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    fn.arg1_type = ARG_PTR_TO_BTF_ID;
    fn.arg2_type = ARG_DONTCARE;
    fn.arg3_type = ARG_DONTCARE;
    fn.arg4_type = ARG_DONTCARE;
    fn.arg5_type = ARG_DONTCARE;
    fn.arg1_btf_id = NULL;
    fn.arg2_btf_id = NULL;
    meta.release_regno = 0;
    BPF_KEEP_SCALAR(fn.arg1_type);
    ret = check_func_proto(&fn, &meta);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    fn.arg1_type = ARG_PTR_TO_BTF_ID;
    fn.arg1_btf_id = &btf_id;
    meta.release_regno = 0;
    BPF_KEEP_SCALAR(fn.arg1_type);
    ret = check_func_proto(&fn, &meta);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);

    fn.arg1_type = ARG_PTR_TO_MEM | MEM_FIXED_SIZE | MEM_WRITE;
    fn.arg1_size = 4;
    fn.arg2_type = ARG_DONTCARE;
    fn.arg3_type = ARG_DONTCARE;
    fn.arg4_type = ARG_DONTCARE;
    fn.arg5_type = ARG_DONTCARE;
    meta.release_regno = 0;
    BPF_KEEP_SCALAR(fn.arg1_type);
    ret = check_func_proto(&fn, &meta);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);

    acc += ret + (int)choice + (int)val;
    return acc;
