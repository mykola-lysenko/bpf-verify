    /* arraymap_prove: verifier-enforced array-map guard/direct-value invariants. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    __u64 choice = input ? *input : 0;
    struct {
        struct bpf_array array;
        u8 value[32];
    } storage = {};
    struct bpf_array *array = &storage.array;
    struct bpf_map *map = &array->map;
    union bpf_attr attr = {};
    struct bpf_map meta0 = {};
    struct bpf_map meta1 = {};
    void *ptr;
    u64 imm = 0;
    u64 base;
    u64 pad;
    u32 key;
    u32 next;
    u32 off;
    u32 meta_off = 0;
    int ret;
    int acc = 0;

    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = 8;
    attr.max_entries = 1;
    attr.map_flags = 0;
    ret = array_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);

    attr.max_entries = 0;
    ret = array_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    attr.max_entries = 1;

    attr.key_size = 8;
    ret = array_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    attr.key_size = 4;

    attr.value_size = 0;
    ret = array_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    attr.value_size = 8;

    attr.map_flags = 1U << 31;
    ret = array_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    attr.map_flags = BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG;
    ret = array_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    attr.map_flags = 0;

    attr.value_size = 0x80000000U;
    ret = array_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -E2BIG);
    attr.value_size = 8;

    attr.map_type = BPF_MAP_TYPE_PERCPU_ARRAY;
    attr.map_flags = BPF_F_NUMA_NODE;
    attr.numa_node = 0;
    ret = array_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    attr.map_flags = 0;
    attr.value_size = PCPU_MIN_UNIT_SIZE + 1;
    ret = array_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -E2BIG);
    attr.value_size = 8;

    attr.map_flags = BPF_F_MMAPABLE;
    ret = array_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.map_flags = BPF_F_PRESERVE_ELEMS;
    ret = array_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    attr.map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
    ret = array_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);

    map->map_type = BPF_MAP_TYPE_ARRAY;
    map->key_size = 4;
    map->value_size = 8;
    map->max_entries = 3;
    map->map_flags = 0;
    array->elem_size = 8;
    array->index_mask = 3;
    storage.value[0] = 0x11;
    storage.value[8] = 0x22;
    storage.value[16] = 0x33;

    key = 1;
    ptr = array_map_lookup_elem(map, &key);
    BPF_PROVE(ptr != NULL);
    BPF_PROVE(*(u8 *)ptr == 0x22);

    key = 3;
    ptr = array_map_lookup_elem(map, &key);
    BPF_PROVE(ptr == NULL);

    key = (u32)(choice & 3);
    BPF_KEEP_SCALAR(key);
    ptr = array_map_lookup_elem(map, &key);
    if (key < 3)
        BPF_ASSERT(ptr != NULL);
    else
        BPF_ASSERT(ptr == NULL);

    next = 99;
    ret = bpf_array_get_next_key(map, NULL, &next);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == 0);
    BPF_ASSERT(next == 0);

    key = 0;
    next = 99;
    ret = bpf_array_get_next_key(map, &key, &next);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == 0);
    BPF_ASSERT(next == 1);

    key = 2;
    next = 99;
    ret = bpf_array_get_next_key(map, &key, &next);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == -ENOENT);
    BPF_ASSERT(next == 99);

    key = 3;
    next = 99;
    ret = bpf_array_get_next_key(map, &key, &next);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == 0);
    BPF_ASSERT(next == 0);

    map->max_entries = 1;
    map->value_size = 8;
    array->elem_size = 8;
    *(volatile u32 *)&map->max_entries = 1;
    *(volatile u32 *)&map->value_size = 8;
    *(volatile u32 *)&array->elem_size = 8;
    off = (u32)((choice >> 4) & 7);
    BPF_KEEP_SCALAR(off);
    ret = array_map_direct_value_addr(map, &imm, off);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == 0);
    BPF_ASSERT(imm == (u64)(unsigned long)array->value);

    ret = array_map_direct_value_meta(map, imm + off, &meta_off);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == 0);
    BPF_ASSERT(meta_off == off);

    ret = array_map_direct_value_addr(map, &imm, 8);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == -EINVAL);

    base = (u64)(unsigned long)array->value;
    ret = array_map_direct_value_meta(map, base - 1, &meta_off);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == -ENOENT);
    ret = array_map_direct_value_meta(map, base + 8, &meta_off);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == -ENOENT);

    map->value_size = 5;
    *(volatile u32 *)&map->value_size = 5;
    ret = array_map_direct_value_addr(map, &imm, 7);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == -EINVAL);
    pad = 7;
    BPF_KEEP_SCALAR(pad);
    ret = array_map_direct_value_meta(map, base + pad, &meta_off);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == 0);
    BPF_ASSERT(meta_off == 7);

    map->max_entries = 2;
    *(volatile u32 *)&map->max_entries = 2;
    ret = array_map_direct_value_addr(map, &imm, 0);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == -ENOTSUPP);
    ret = array_map_direct_value_meta(map, base, &meta_off);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == -ENOTSUPP);

    meta0.map_type = BPF_MAP_TYPE_ARRAY;
    meta0.key_size = 4;
    meta0.value_size = 8;
    meta0.map_flags = 0;
    meta0.max_entries = 3;
    meta0.record = NULL;
    meta1 = meta0;
    BPF_ASSERT(array_map_meta_equal(&meta0, &meta1));
    meta1.max_entries = 4;
    BPF_ASSERT(!array_map_meta_equal(&meta0, &meta1));
    meta0.map_flags = BPF_F_INNER_MAP;
    meta1.map_flags = BPF_F_INNER_MAP;
    BPF_ASSERT(array_map_meta_equal(&meta0, &meta1));
    meta1.value_size = 16;
    BPF_ASSERT(!array_map_meta_equal(&meta0, &meta1));

    acc += ret + (int)next + (int)meta_off;
    return (int)choice + acc;
