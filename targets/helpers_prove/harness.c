    /* helpers_prove: base helper prototype routing and small helper guards. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    __u64 choice = input ? *input : 0;
    struct bpf_token no_caps = {};
    struct bpf_token bpf_caps = { .caps = 1ULL << CAP_BPF };
    struct bpf_token perf_caps = {
        .caps = (1ULL << CAP_BPF) | (1ULL << CAP_PERFMON),
    };
    struct bpf_prog_aux aux = { .token = &no_caps };
    struct bpf_prog prog = { .aux = &aux };
    const struct bpf_func_proto *proto;
    struct bpf_map map = {};
    struct bpf_array array = {};
    struct task_struct task = {};
    char values[32] = {};
    char dst[8] = {};
    char src[8] = {};
    void *ptr;
    u32 arr_idx = 99;
    enum bpf_func_id fid;
    u64 flags;
    u64 ret;
    int x = 42;
    int acc = 0;

    fid = BPF_FUNC_map_lookup_elem;
    BPF_KEEP_SCALAR(fid);
    proto = bpf_base_func_proto(fid, &prog);
    BPF_PROVE(proto == &bpf_map_lookup_elem_proto);
    BPF_PROVE(proto->ret_type == RET_PTR_TO_MAP_VALUE_OR_NULL);
    BPF_PROVE(proto->arg1_type == ARG_CONST_MAP_PTR);
    BPF_PROVE(proto->arg2_type == ARG_PTR_TO_MAP_KEY);
    BPF_PROVE(proto->pkt_access);

    fid = BPF_FUNC_map_update_elem;
    BPF_KEEP_SCALAR(fid);
    proto = bpf_base_func_proto(fid, &prog);
    BPF_PROVE(proto == &bpf_map_update_elem_proto);
    BPF_PROVE(proto->arg3_type == ARG_PTR_TO_MAP_VALUE);
    BPF_PROVE(proto->arg4_type == ARG_ANYTHING);

    fid = BPF_FUNC_map_pop_elem;
    BPF_KEEP_SCALAR(fid);
    proto = bpf_base_func_proto(fid, &prog);
    BPF_PROVE(proto == &bpf_map_pop_elem_proto);
    BPF_PROVE(proto->arg2_type ==
              (ARG_PTR_TO_MAP_VALUE | MEM_UNINIT | MEM_WRITE));

    fid = BPF_FUNC_strtol;
    BPF_KEEP_SCALAR(fid);
    proto = bpf_base_func_proto(fid, &prog);
    BPF_PROVE(proto == &bpf_strtol_proto);
    BPF_PROVE(proto->arg1_type == (ARG_PTR_TO_MEM | MEM_RDONLY));
    BPF_PROVE(proto->arg4_type ==
              (ARG_PTR_TO_FIXED_SIZE_MEM | MEM_UNINIT | MEM_WRITE |
               MEM_ALIGNED));
    BPF_PROVE(proto->arg4_size == sizeof(s64));

    fid = BPF_FUNC_strtoul;
    BPF_KEEP_SCALAR(fid);
    proto = bpf_base_func_proto(fid, &prog);
    BPF_PROVE(proto == &bpf_strtoul_proto);
    BPF_PROVE(proto->arg4_size == sizeof(u64));

    fid = BPF_FUNC_strncmp;
    BPF_KEEP_SCALAR(fid);
    proto = bpf_base_func_proto(fid, &prog);
    BPF_PROVE(proto == &bpf_strncmp_proto);
    BPF_PROVE(proto->arg3_type == ARG_PTR_TO_CONST_STR);

    fid = BPF_FUNC_get_ns_current_pid_tgid;
    BPF_KEEP_SCALAR(fid);
    proto = bpf_base_func_proto(fid, &prog);
    BPF_PROVE(proto == &bpf_get_ns_current_pid_tgid_proto);
    BPF_PROVE(proto->arg3_type == ARG_PTR_TO_UNINIT_MEM);
    BPF_PROVE(proto->arg4_type == ARG_CONST_SIZE);

    fid = BPF_FUNC_unspec;
    BPF_KEEP_SCALAR(fid);
    BPF_PROVE(bpf_base_func_proto(fid, &prog) == NULL);
    fid = BPF_FUNC_spin_lock;
    BPF_KEEP_SCALAR(fid);
    BPF_PROVE(bpf_base_func_proto(fid, &prog) == NULL);
    fid = BPF_FUNC_get_current_comm;
    BPF_KEEP_SCALAR(fid);
    BPF_PROVE(bpf_base_func_proto(fid, &prog) == NULL);

    aux.token = &bpf_caps;
    fid = BPF_FUNC_spin_lock;
    BPF_KEEP_SCALAR(fid);
    proto = bpf_base_func_proto(fid, &prog);
    BPF_PROVE(proto == &bpf_spin_lock_proto);
    BPF_PROVE(proto->ret_type == RET_VOID);
    BPF_PROVE(proto->arg1_type == ARG_PTR_TO_SPIN_LOCK);
    fid = BPF_FUNC_per_cpu_ptr;
    BPF_KEEP_SCALAR(fid);
    proto = bpf_base_func_proto(fid, &prog);
    BPF_PROVE(proto == &bpf_per_cpu_ptr_proto);
    BPF_PROVE(proto->ret_type ==
              (RET_PTR_TO_MEM_OR_BTF_ID | PTR_MAYBE_NULL | MEM_RDONLY));
    fid = BPF_FUNC_this_cpu_ptr;
    BPF_KEEP_SCALAR(fid);
    proto = bpf_base_func_proto(fid, &prog);
    BPF_PROVE(proto == &bpf_this_cpu_ptr_proto);
    BPF_PROVE(proto->ret_type == (RET_PTR_TO_MEM_OR_BTF_ID | MEM_RDONLY));
    fid = BPF_FUNC_kptr_xchg;
    BPF_KEEP_SCALAR(fid);
    proto = bpf_base_func_proto(fid, &prog);
    BPF_PROVE(proto == &bpf_kptr_xchg_proto);
    BPF_PROVE(proto->arg2_type ==
              (ARG_PTR_TO_BTF_ID_OR_NULL | OBJ_RELEASE));
    fid = BPF_FUNC_get_current_comm;
    BPF_KEEP_SCALAR(fid);
    BPF_PROVE(bpf_base_func_proto(fid, &prog) == NULL);

    aux.token = &perf_caps;
    fid = BPF_FUNC_get_current_comm;
    BPF_KEEP_SCALAR(fid);
    proto = bpf_base_func_proto(fid, &prog);
    BPF_PROVE(proto == &bpf_get_current_comm_proto);
    BPF_PROVE(proto->arg1_type == ARG_PTR_TO_UNINIT_MEM);
    BPF_PROVE(proto->arg2_type == ARG_CONST_SIZE);
    fid = BPF_FUNC_copy_from_user_task;
    BPF_KEEP_SCALAR(fid);
    proto = bpf_base_func_proto(fid, &prog);
    BPF_PROVE(proto == &bpf_copy_from_user_task_proto);
    BPF_PROVE(proto->might_sleep);
    BPF_PROVE(proto->arg5_type == ARG_ANYTHING);

    prog.sleepable = false;
    fid = BPF_FUNC_get_task_stack;
    BPF_KEEP_SCALAR(fid);
    proto = bpf_base_func_proto(fid, &prog);
    BPF_PROVE(proto == &bpf_get_task_stack_proto);
    prog.sleepable = true;
    fid = BPF_FUNC_get_task_stack;
    BPF_KEEP_SCALAR(fid);
    proto = bpf_base_func_proto(fid, &prog);
    BPF_PROVE(proto == &bpf_get_task_stack_sleepable_proto);

    BPF_PROVE(bpf_event_output_data(NULL, &map, BPF_F_INDEX_MASK,
                                    values, 0) == 0);
    flags = 1ULL << 32;
    BPF_KEEP_SCALAR(flags);
    ret = bpf_event_output_data(NULL, &map, flags, values, 0);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    BPF_PROVE(bpf_event_output_data_proto.gpl_only);
    BPF_PROVE(bpf_event_output_data_proto.arg4_type ==
              (ARG_PTR_TO_MEM | MEM_RDONLY));
    BPF_PROVE(bpf_event_output_data_proto.arg5_type ==
              ARG_CONST_SIZE_OR_ZERO);

    ret = bpf_copy_from_user_task(dst, 0, src, &task, 0);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = bpf_copy_from_user_task(dst, 4, src, &task, 1);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    ret = bpf_copy_from_user_task(dst, 4, src, &task, 0);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    dst[0] = 7;
    ret = bpf_copy_from_user_task(dst, 3, src, &task, 0);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EFAULT);
    BPF_PROVE(dst[0] == 0);

    ret = bpf_per_cpu_ptr(&x, 2);
    BPF_ASSERT(ret == (u64)(unsigned long)&x);
    ret = bpf_per_cpu_ptr(&x, HELPERS_TEST_NR_CPUS);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = bpf_this_cpu_ptr(&x);
    BPF_ASSERT(ret == (u64)(unsigned long)&x);

    array.map.map_type = BPF_MAP_TYPE_ARRAY;
    array.elem_size = 8;
    array.value = values;
    ptr = map_key_from_value(&array.map, &values[16], &arr_idx);
    BPF_ASSERT(ptr == &arr_idx);
    BPF_ASSERT(arr_idx == 2);
    map.map_type = BPF_MAP_TYPE_HASH;
    map.key_size = 5;
    ptr = map_key_from_value(&map, &values[16], &arr_idx);
    BPF_ASSERT(ptr == &values[8]);

    acc += (int)choice + (int)arr_idx;
    return acc;
