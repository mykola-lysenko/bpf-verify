    /* bpf_struct_ops lifecycle: syscall lookup, link info/poll, and update
     * guard ordering. The callback-bearing update swap is shimmed out. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    __u64 choice = input ? *input : 0;
    struct {
        struct bpf_struct_ops_map st_map;
        char data[32];
    } storage = {};
    struct {
        struct bpf_struct_ops_value value;
        char data[32];
    } uvalue = {}, lookup = {};
    struct bpf_struct_ops_map *st_map = &storage.st_map;
    struct bpf_map *map = &st_map->map;
    struct btf_type value_type = {
        .size = sizeof(struct bpf_struct_ops_value) + sizeof(storage.data),
    };
    struct btf_type type = { .size = 16 };
    struct bpf_struct_ops ops = {};
    struct bpf_struct_ops_desc desc = {
        .st_ops = &ops,
        .type = &type,
        .value_type = &value_type,
    };
    struct btf btf = { .id = 321 };
    struct bpf_struct_ops_link link = {};
    struct bpf_link_info link_info = {};
    struct file file = {};
    u32 key = 0;
    int ret;

    st_map->st_ops_desc = &desc;
    st_map->btf = &btf;
    st_map->uvalue = &uvalue.value;
    map->map_type = BPF_MAP_TYPE_STRUCT_OPS;
    map->map_flags = BPF_F_LINK;
    map->id = 88;
    map->value_size = value_type.size;
    atomic64_set(&map->refcnt, 5);
    atomic64_set(&map->usercnt, 2);
    BPF_KEEP_SCALAR(map->map_type);
    BPF_KEEP_SCALAR(map->map_flags);
    BPF_KEEP_SCALAR(map->id);

    key = 1;
    ret = bpf_struct_ops_map_sys_lookup_elem(map, &key, &lookup.value);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == -ENOENT);

    key = 0;
    lookup.data[0] = 99;
    st_map->kvalue.common.state = BPF_STRUCT_OPS_STATE_INIT;
    ret = bpf_struct_ops_map_sys_lookup_elem(map, &key, &lookup.value);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == 0);
    BPF_ASSERT(lookup.value.common.state == BPF_STRUCT_OPS_STATE_INIT);
    BPF_ASSERT(lookup.value.common.refcnt.refs == 0);
    BPF_ASSERT(lookup.data[0] == 0);

    uvalue.data[0] = 42;
    uvalue.value.common.refcnt.refs = 99;
    st_map->kvalue.common.state = BPF_STRUCT_OPS_STATE_READY;
    ret = bpf_struct_ops_map_sys_lookup_elem(map, &key, &lookup.value);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == 0);
    BPF_ASSERT(lookup.value.common.state == BPF_STRUCT_OPS_STATE_READY);
    BPF_ASSERT(lookup.value.common.refcnt.refs == 3);
    BPF_ASSERT(lookup.data[0] == 42);

    atomic64_set(&map->refcnt, 1);
    atomic64_set(&map->usercnt, 5);
    ret = bpf_struct_ops_map_sys_lookup_elem(map, &key, &lookup.value);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == 0);
    BPF_ASSERT(lookup.value.common.refcnt.refs == 0);

    link.map = map;
    ret = bpf_struct_ops_map_link_fill_link_info(&link.link, &link_info);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == 0);
    BPF_ASSERT(link_info.struct_ops.map_id == 88);

    link.map = NULL;
    link_info.struct_ops.map_id = 123;
    ret = bpf_struct_ops_map_link_fill_link_info(&link.link, &link_info);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == 0);
    BPF_ASSERT(link_info.struct_ops.map_id == 123);

    file.private_data = &link;
    BPF_ASSERT(bpf_struct_ops_map_link_poll(&file, NULL) == EPOLLHUP);
    link.map = map;
    BPF_ASSERT(bpf_struct_ops_map_link_poll(&file, NULL) == 0);

    map->map_flags = 0;
    ret = bpf_struct_ops_map_link_update(&link.link, map, NULL);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == -EINVAL);

    map->map_flags = BPF_F_LINK;
    ops.update = NULL;
    ret = bpf_struct_ops_map_link_update(&link.link, map, NULL);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == -EOPNOTSUPP);

    ops.update = (int (*)(void *, void *, struct bpf_link *))1;
    link.map = NULL;
    ret = bpf_struct_ops_map_link_update(&link.link, map, NULL);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == -ENOLINK);

    link.map = map;
    ret = bpf_struct_ops_map_link_update(&link.link, map,
                                         (struct bpf_map *)&lookup.value);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == -EPERM);

    ret = bpf_struct_ops_map_link_update(&link.link, map, NULL);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == 0);

    return (int)(choice + ret + key + lookup.value.common.refcnt.refs +
                 link_info.struct_ops.map_id);
