    /* bpf_insn_array: verifier/JIT instruction jump-table metadata.
     *
     * The target-specific pre-include models only the BPF map, program, BTF,
     * and atomic fields touched by this file. The harness keeps max_entries
     * fixed at three so offset adjustment and JIT pointer update loops stay
     * verifier-trackable.
     *
     * Covered here:
     *   1. Allocation sizing, attribute validation, lookup/update/delete, and
     *      direct-value address helpers.
     *   2. BTF checks and frozen-map init/release/used-state handling.
     *   3. Offset adjustment, deleted-entry handling, ready checks, and JIT
     *      instruction pointer finalization.
     */
    struct __bpf_insn_array_alloc storage;
    struct bpf_insn_array *insn_array = &storage.insn_array;
    struct bpf_map *map = &insn_array->map;
    union bpf_attr attr = {};
    struct bpf_insn_array_value update = {};
    struct bpf_insn_array_value *lookup;
    struct bpf_map *alloc_map;
    struct btf_type i32_type = { .kind = 32 };
    struct btf_type i64_type = { .kind = 64 };
    struct btf_type bad_type = { .kind = 1 };
    struct bpf_insn insns[8] = {};
    struct bpf_prog_aux aux = {};
    struct bpf_prog prog = {};
    struct bpf_map *maps[1];
    u32 offsets[8] = {};
    u8 image[64] = {};
    u32 key0 = 0, key1 = 1, key2 = 2, next = 0;
    u64 imm = 0;

    __bpf_insn_array_zero(&storage);
    map->map_type = BPF_MAP_TYPE_INSN_ARRAY;
    map->key_size = 4;
    map->value_size = sizeof(struct bpf_insn_array_value);
    map->max_entries = 3;
    map->map_flags = 0;
    map->numa_node = NUMA_NO_NODE;
    map->frozen = true;
    insn_array->ips = storage.ips;
    insn_array->values[0].orig_off = 1;
    insn_array->values[1].orig_off = 3;
    insn_array->values[2].orig_off = 5;

    BPF_ASSERT(insn_array_alloc_size(3) == sizeof(storage));
    attr.key_size = 4;
    attr.value_size = sizeof(struct bpf_insn_array_value);
    attr.max_entries = 3;
    BPF_ASSERT(insn_array_alloc_check(&attr) == 0);
    attr.map_flags = BPF_F_RDONLY_PROG;
    BPF_ASSERT(insn_array_alloc_check(&attr) == -EINVAL);
    attr.map_flags = 0;
    attr.key_size = 8;
    BPF_ASSERT(insn_array_alloc_check(&attr) == -EINVAL);
    attr.key_size = 4;

    lookup = insn_array_lookup_elem(map, &key1);
    BPF_ASSERT(lookup == &insn_array->values[1]);
    BPF_ASSERT(insn_array_lookup_elem(map, &key2) ==
               &insn_array->values[2]);
    key2 = 3;
    BPF_ASSERT(insn_array_lookup_elem(map, &key2) == 0);
    key2 = 2;

    update.orig_off = 2;
    BPF_ASSERT(insn_array_update_elem(map, &key0, &update, 0) == 0);
    BPF_ASSERT(insn_array->values[0].orig_off == 2);
    BPF_ASSERT(insn_array_update_elem(map, &key0, &update,
                                      BPF_NOEXIST) == -EEXIST);
    update.jitted_off = 1;
    BPF_ASSERT(insn_array_update_elem(map, &key0, &update, 0) == -EINVAL);
    update.jitted_off = 0;
    key2 = 3;
    BPF_ASSERT(insn_array_update_elem(map, &key2, &update, 0) == -E2BIG);
    key2 = 2;
    insn_array->values[0].orig_off = 1;

    BPF_ASSERT(insn_array_delete_elem(map, &key0) == -EINVAL);
    BPF_ASSERT(bpf_array_get_next_key(map, 0, &next) == 0);
    BPF_ASSERT(next == 0);
    BPF_ASSERT(bpf_array_get_next_key(map, &key1, &next) == 0);
    BPF_ASSERT(next == 2);
    BPF_ASSERT(bpf_array_get_next_key(map, &key2, &next) == -ENOENT);

    BPF_ASSERT(insn_array_check_btf(map, 0, &i32_type, &i64_type) == 0);
    BPF_ASSERT(insn_array_check_btf(map, 0, &bad_type, &i64_type) == -EINVAL);
    BPF_ASSERT(insn_array_check_btf(map, 0, &i32_type, &bad_type) == -EINVAL);
    BPF_ASSERT(insn_array_mem_usage(map) == sizeof(storage));
    BPF_ASSERT(insn_array_map_direct_value_addr(map, &imm, 0) == 0);
    BPF_ASSERT(imm == (u64)(unsigned long)insn_array->ips);
    BPF_ASSERT(insn_array_map_direct_value_addr(map, &imm,
               sizeof(long) * 3) == -EACCES);
    BPF_ASSERT(insn_array_map_direct_value_addr(map, &imm, 4) == -EACCES);

    maps[0] = map;
    aux.used_map_cnt = 1;
    aux.used_maps = maps;
    aux.subprog_start = 1;
    prog.len = 8;
    prog.insnsi = insns;
    prog.aux = &aux;
    BPF_ASSERT(bpf_insn_array_init(map, &prog) == 0);
    BPF_ASSERT(insn_array->values[0].xlated_off == 1);
    BPF_ASSERT(insn_array->values[1].xlated_off == 3);
    BPF_ASSERT(insn_array->values[2].xlated_off == 5);
    BPF_ASSERT(bpf_insn_array_init(map, &prog) == -EBUSY);
    bpf_insn_array_release(map);
    BPF_ASSERT(insn_array->used.counter == 0);

    BPF_ASSERT(bpf_insn_array_ready(map) == -EFAULT);
    bpf_insn_array_adjust(map, 2, 3);
    BPF_ASSERT(insn_array->values[0].xlated_off == 1);
    BPF_ASSERT(insn_array->values[1].xlated_off == 5);
    BPF_ASSERT(insn_array->values[2].xlated_off == 7);
    bpf_insn_array_adjust_after_remove(map, 5, 2);
    BPF_ASSERT(insn_array->values[0].xlated_off == 1);
    BPF_ASSERT(insn_array->values[1].xlated_off == INSN_DELETED);
    BPF_ASSERT(insn_array->values[2].xlated_off == 5);

    offsets[0] = 8;
    offsets[4] = 24;
    bpf_prog_update_insn_ptrs(&prog, offsets, image);
    BPF_ASSERT(insn_array->values[0].jitted_off == 8);
    BPF_ASSERT(insn_array->values[2].jitted_off == 24);
    BPF_ASSERT(insn_array->ips[0] == (long)(image + 8));
    BPF_ASSERT(insn_array->ips[2] == (long)(image + 24));
    BPF_ASSERT(bpf_insn_array_ready(map) == 0);

    __bpf_insn_array_allocated = 0;
    alloc_map = insn_array_alloc(&attr);
    BPF_ASSERT(alloc_map == &__bpf_insn_array_alloc.insn_array.map);
    BPF_ASSERT(__bpf_insn_array_alloc.insn_array.map.map_flags ==
               BPF_F_RDONLY_PROG);
    BPF_ASSERT(__bpf_insn_array_alloc.insn_array.ips ==
               __bpf_insn_array_alloc.ips);
    insn_array_free(alloc_map);
    BPF_ASSERT(__bpf_insn_array_allocated == 0);

    return (int)(insn_array->values[2].jitted_off + next);
