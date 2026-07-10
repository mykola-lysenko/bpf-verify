    /* map_in_map_prove: verifier-enforced metadata equality invariants.
     *
     * The copy path through bpf_map_meta_alloc() is covered by map_in_map with
     * BPF_ASSERT. This proof keeps metadata on stack so BPF_PROVE can track
     * fields precisely, then checks equality/mismatch and fd-put semantics.
     */
    __u32 key = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &key);
    if (!vp) return 0;

    struct bpf_map meta = {};
    struct bpf_map inner = {};
    struct bpf_map outer = {};
    u32 map_type = (u32)(*vp & 0xff) + 1;
    u32 key_size = (u32)((*vp >> 8) & 0xff) + 1;
    u32 value_size = (u32)((*vp >> 16) & 0xff) + 1;
    u32 flags = (u32)((*vp >> 24) & 0xff);

    meta.map_type = map_type;
    meta.key_size = key_size;
    meta.value_size = value_size;
    meta.map_flags = flags;
    meta.record = &__bpf_map_in_map_record;

    inner.map_type = map_type;
    inner.key_size = key_size;
    inner.value_size = value_size;
    inner.map_flags = flags;
    inner.record = &__bpf_map_in_map_record;

    BPF_PROVE(bpf_map_meta_equal(&meta, &inner));
    inner.map_type = map_type + 1;
    BPF_PROVE(!bpf_map_meta_equal(&meta, &inner));
    inner.map_type = map_type;
    inner.key_size = key_size + 1;
    BPF_PROVE(!bpf_map_meta_equal(&meta, &inner));
    inner.key_size = key_size;
    inner.value_size = value_size + 1;
    BPF_PROVE(!bpf_map_meta_equal(&meta, &inner));
    inner.value_size = value_size;
    inner.map_flags = flags + 1;
    BPF_PROVE(!bpf_map_meta_equal(&meta, &inner));
    inner.map_flags = flags;
    inner.record = 0;
    BPF_PROVE(!bpf_map_meta_equal(&meta, &inner));
    inner.record = &__bpf_map_in_map_record;
    BPF_PROVE(bpf_map_meta_equal(&meta, &inner));

    outer.sleepable_refcnt.counter = 1;
    bpf_map_fd_put_ptr(&outer, &inner, true);
    BPF_PROVE(inner.free_after_mult_rcu_gp);
    BPF_PROVE(!inner.free_after_rcu_gp);
    inner.free_after_mult_rcu_gp = false;
    outer.sleepable_refcnt.counter = 0;
    bpf_map_fd_put_ptr(&outer, &inner, true);
    BPF_PROVE(inner.free_after_rcu_gp);
    inner.free_after_rcu_gp = false;
    bpf_map_fd_put_ptr(&outer, &inner, false);
    BPF_PROVE(!inner.free_after_mult_rcu_gp);
    BPF_PROVE(!inner.free_after_rcu_gp);
    inner.id = map_type;
    BPF_PROVE(bpf_map_fd_sys_lookup_elem(&inner) == map_type);

    return (int)(map_type + key_size + value_size + flags);
