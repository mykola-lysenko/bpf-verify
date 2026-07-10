    /* bpf_struct_ops_prove: struct-ops map guard and metadata invariants. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    __u64 choice = input ? *input : 0;
    struct {
        struct bpf_struct_ops_map st_map;
        char data[32];
    } storage = {};
    struct bpf_struct_ops_map *st_map = &storage.st_map;
    struct bpf_map *map = &st_map->map;
    struct btf_type value_type = {
        .size = sizeof(struct bpf_struct_ops_value) + sizeof(storage.data),
    };
    struct btf_type type = { .size = 16 };
    struct bpf_struct_ops_desc desc = {
        .type = &type,
        .value_type = &value_type,
    };
    struct btf btf = { .id = 123 };
    struct bpf_map_info info = {};
    union bpf_attr attr = {};
    void *stubs[2] = { NULL, &storage };
    struct bpf_struct_ops ops = { .cfi_stubs = stubs };
    u64 expected_usage;
    u32 key;
    u32 next;
    int ret;
    int acc = 0;

    attr.key_size = sizeof(unsigned int);
    attr.max_entries = 1;
    attr.btf_vmlinux_value_type_id = 1;
    attr.map_flags = 0;
    BPF_KEEP_SCALAR(attr.key_size);
    BPF_KEEP_SCALAR(attr.max_entries);
    BPF_KEEP_SCALAR(attr.btf_vmlinux_value_type_id);
    BPF_KEEP_SCALAR(attr.map_flags);
    ret = bpf_struct_ops_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);

    attr.map_flags = BPF_F_LINK | BPF_F_VTYPE_BTF_OBJ_FD;
    BPF_KEEP_SCALAR(attr.map_flags);
    ret = bpf_struct_ops_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);

    attr.key_size = sizeof(unsigned int) + 1;
    BPF_KEEP_SCALAR(attr.key_size);
    ret = bpf_struct_ops_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    attr.key_size = sizeof(unsigned int);

    attr.max_entries = 0;
    BPF_KEEP_SCALAR(attr.max_entries);
    ret = bpf_struct_ops_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    attr.max_entries = 2;
    BPF_KEEP_SCALAR(attr.max_entries);
    ret = bpf_struct_ops_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    attr.max_entries = 1;

    attr.map_flags = 1U << 31;
    BPF_KEEP_SCALAR(attr.map_flags);
    ret = bpf_struct_ops_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    attr.map_flags = 0;

    attr.btf_vmlinux_value_type_id = 0;
    BPF_KEEP_SCALAR(attr.btf_vmlinux_value_type_id);
    ret = bpf_struct_ops_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    attr.btf_vmlinux_value_type_id = 1;

    next = 99;
    ret = bpf_struct_ops_map_get_next_key(map, NULL, &next);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == 0);
    BPF_ASSERT(next == 0);

    key = 0;
    next = 99;
    ret = bpf_struct_ops_map_get_next_key(map, &key, &next);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == -ENOENT);
    BPF_ASSERT(next == 99);

    key = 7;
    next = 99;
    ret = bpf_struct_ops_map_get_next_key(map, &key, &next);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == 0);
    BPF_ASSERT(next == 0);

    key = (u32)(choice & 1);
    BPF_KEEP_SCALAR(key);
    BPF_ASSERT(PTR_ERR(bpf_struct_ops_map_lookup_elem(map, &key)) == -EINVAL);

    ret = bpf_struct_ops_supported(&ops, 0);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == -ENOTSUPP);
    ret = bpf_struct_ops_supported(&ops, sizeof(void *));
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == 0);

    st_map->st_ops_desc = &desc;
    st_map->btf = &btf;
    st_map->funcs_cnt = 3;
    map->id = 77;
    map->map_type = BPF_MAP_TYPE_STRUCT_OPS;
    map->map_flags = BPF_F_LINK;
    atomic64_set(&map->refcnt, 1);
    st_map->kvalue.common.state = BPF_STRUCT_OPS_STATE_READY;
    BPF_KEEP_SCALAR(st_map->funcs_cnt);
    BPF_KEEP_SCALAR(map->id);
    BPF_KEEP_SCALAR(map->map_type);
    BPF_KEEP_SCALAR(map->map_flags);
    BPF_KEEP_SCALAR(st_map->kvalue.common.state);

    expected_usage = sizeof(struct bpf_struct_ops_map) +
                     value_type.size - sizeof(struct bpf_struct_ops_value);
    expected_usage += value_type.size;
    expected_usage += 3 * sizeof(struct bpf_link *);
    expected_usage += 3 * sizeof(struct bpf_ksym *);
    expected_usage += PAGE_SIZE;
    BPF_ASSERT(bpf_struct_ops_map_mem_usage(map) == expected_usage);
    BPF_ASSERT(bpf_struct_ops_valid_to_reg(map));
    BPF_ASSERT(bpf_struct_ops_id(st_map->kvalue.data) == 77);

    bpf_map_struct_ops_info_fill(&info, map);
    BPF_ASSERT(info.btf_vmlinux_id == 123);

    BPF_ASSERT(bpf_struct_ops_get(st_map->kvalue.data));
    BPF_ASSERT(map->refcnt.counter == 2);
    bpf_struct_ops_put(st_map->kvalue.data);
    BPF_ASSERT(map->refcnt.counter == 1);

    map->map_flags = 0;
    BPF_ASSERT(!bpf_struct_ops_valid_to_reg(map));
    map->map_flags = BPF_F_LINK;
    map->map_type = 0;
    BPF_ASSERT(!bpf_struct_ops_valid_to_reg(map));
    map->map_type = BPF_MAP_TYPE_STRUCT_OPS;
    st_map->kvalue.common.state = BPF_STRUCT_OPS_STATE_INUSE;
    BPF_ASSERT(!bpf_struct_ops_valid_to_reg(map));

    atomic64_set(&map->refcnt, 0);
    BPF_ASSERT(!bpf_struct_ops_get(st_map->kvalue.data));

    acc += ret + (int)next + (int)info.btf_vmlinux_id;
    return (int)choice + acc;
