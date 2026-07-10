    /* bpf_insn_array_prove: verifier-enforced allocation/direct-value bounds.
     *
     * Proves the symbolic allocation-size formula, allocation attribute
     * acceptance/rejection cases, and direct-value address validation for
     * aligned in-bounds, aligned out-of-bounds, and unaligned offsets.
     */
    __u32 key = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &key);
    if (!vp) return 0;

    struct __bpf_insn_array_alloc storage;
    struct bpf_insn_array *insn_array = &storage.insn_array;
    struct bpf_map *map = &insn_array->map;
    union bpf_attr attr = {};
    u32 entries = (u32)(*vp & 3) + 1;
    u64 expected = sizeof(struct bpf_insn_array) +
                   (u64)entries *
                   (sizeof(struct bpf_insn_array_value) + sizeof(long));
    u64 imm = 0;
    u32 index = (u32)((*vp >> 8) & 3);
    u32 off = index * sizeof(long);
    int ret;

    BPF_PROVE(insn_array_alloc_size(entries) == expected);

    attr.key_size = 4;
    attr.value_size = sizeof(struct bpf_insn_array_value);
    attr.max_entries = entries;
    attr.map_flags = 0;
    BPF_PROVE(insn_array_alloc_check(&attr) == 0);
    attr.max_entries = 0;
    BPF_PROVE(insn_array_alloc_check(&attr) == -EINVAL);
    attr.max_entries = entries;
    attr.key_size = 8;
    BPF_PROVE(insn_array_alloc_check(&attr) == -EINVAL);
    attr.key_size = 4;
    attr.value_size = sizeof(struct bpf_insn_array_value) + 8;
    BPF_PROVE(insn_array_alloc_check(&attr) == -EINVAL);
    attr.value_size = sizeof(struct bpf_insn_array_value);
    attr.map_flags = BPF_F_RDONLY_PROG;
    BPF_PROVE(insn_array_alloc_check(&attr) == -EINVAL);

    __bpf_insn_array_zero(&storage);
    map->value_size = sizeof(struct bpf_insn_array_value);
    map->max_entries = 3;
    insn_array->ips = storage.ips;

    ret = insn_array_map_direct_value_addr(map, &imm, off);
    if (index < 3) {
        BPF_PROVE(ret == 0);
        BPF_PROVE(imm == (u64)(unsigned long)storage.ips);
    } else {
        BPF_PROVE(ret == -EACCES);
    }

    BPF_PROVE(insn_array_map_direct_value_addr(map, &imm,
                                               off + 4) == -EACCES);

    return (int)(entries + index + off);
