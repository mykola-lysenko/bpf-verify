    /* map_in_map: metadata handling for BPF map-in-map targets.
     *
     * Covered here:
     *   1. bpf_map_meta_alloc() copies base and array-specific metadata.
     *   2. bpf_map_meta_equal() compares structural metadata and BTF records.
     *   3. bpf_map_fd_put_ptr() deferred-free flags and bpf_map_fd_sys_lookup_elem().
     *
     * bpf_map_fd_get_ptr() is intentionally not called: the real source calls
     * map_meta_equal through map ops, which becomes a BPF indirect call.
     */
    struct bpf_array *inner_array = &__bpf_map_in_map_inner_array;
    struct bpf_map *inner = &inner_array->map;
    struct bpf_map *meta;
    struct bpf_array *meta_array;
    struct bpf_map outer = {};

    __bpf_map_in_map_zero_array(inner_array);
    inner->ops = &array_map_ops;
    inner->map_type = 42;
    inner->key_size = 4;
    inner->value_size = 8;
    inner->map_flags = 3;
    inner->max_entries = 16;
    inner->id = 1234;
    inner->record = &__bpf_map_in_map_record;
    inner->btf = &__bpf_map_in_map_btf;
    inner->bypass_spec_v1 = true;
    inner_array->elem_size = 16;
    inner_array->index_mask = 31;
    __bpf_map_in_map_allocated = 0;

    meta = bpf_map_meta_alloc(11);
    BPF_ASSERT(meta == &__bpf_map_in_map_meta_array.map);
    BPF_ASSERT(meta->map_type == inner->map_type);
    BPF_ASSERT(meta->key_size == inner->key_size);
    BPF_ASSERT(meta->value_size == inner->value_size);
    BPF_ASSERT(meta->map_flags == inner->map_flags);
    BPF_ASSERT(meta->max_entries == inner->max_entries);
    BPF_ASSERT(meta->record == inner->record);
    BPF_ASSERT(meta->btf == inner->btf);
    BPF_ASSERT(meta->ops == &array_map_ops);
    BPF_ASSERT(meta->bypass_spec_v1 == true);
    meta_array = container_of(meta, struct bpf_array, map);
    BPF_ASSERT(meta_array->index_mask == inner_array->index_mask);
    BPF_ASSERT(meta_array->elem_size == inner_array->elem_size);
    BPF_ASSERT(bpf_map_meta_equal(meta, inner));
    inner->value_size = 16;
    BPF_ASSERT(!bpf_map_meta_equal(meta, inner));
    inner->value_size = 8;
    bpf_map_meta_free(meta);
    BPF_ASSERT(__bpf_map_in_map_allocated == 0);

    inner->inner_map_meta = inner;
    meta = bpf_map_meta_alloc(11);
    BPF_ASSERT(IS_ERR(meta));
    BPF_ASSERT(PTR_ERR(meta) == -EINVAL);
    inner->inner_map_meta = 0;
    inner->ops = &__bpf_map_in_map_no_meta_ops;
    meta = bpf_map_meta_alloc(11);
    BPF_ASSERT(IS_ERR(meta));
    BPF_ASSERT(PTR_ERR(meta) == -ENOTSUPP);
    inner->ops = &array_map_ops;
    meta = bpf_map_meta_alloc(-1);
    BPF_ASSERT(IS_ERR(meta));
    BPF_ASSERT(PTR_ERR(meta) == -EBADF);

    outer.sleepable_refcnt.counter = 1;
    bpf_map_fd_put_ptr(&outer, inner, true);
    BPF_ASSERT(inner->free_after_mult_rcu_gp);
    BPF_ASSERT(!inner->free_after_rcu_gp);
    BPF_ASSERT(__bpf_map_in_map_puts == 1);
    inner->free_after_mult_rcu_gp = false;
    outer.sleepable_refcnt.counter = 0;
    bpf_map_fd_put_ptr(&outer, inner, true);
    BPF_ASSERT(inner->free_after_rcu_gp);
    BPF_ASSERT(__bpf_map_in_map_puts == 2);
    BPF_ASSERT(bpf_map_fd_sys_lookup_elem(inner) == 1234);

    return __bpf_map_in_map_puts;
