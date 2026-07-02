    /* queue_stack_maps: BPF queue/stack map data-path helpers.
     *
     * The target-specific pre-include provides the small bpf_map surface used
     * by this source file and keeps element storage local, so the verifier can
     * track queue indexes and element copies precisely.
     *
     * Covered here:
     *   1. Queue FIFO push/peek/pop behavior and empty-pop zeroing.
     *   2. Stack top lookup/pop behavior and BPF_EXIST full-map replacement.
     *   3. Attribute validation plus allocator success/free paths.
     */
    struct {
        struct bpf_queue_stack qs;
        u8 data[32];
    } storage;
    struct bpf_queue_stack *qs = &storage.qs;
    struct bpf_map *map = &qs->map;
    u64 in0 = 0x1111111111111111ULL;
    u64 in1 = 0x2222222222222222ULL;
    u64 in2 = 0x3333333333333333ULL;
    u64 in3 = 0x4444444444444444ULL;
    u64 out = 0;
    union bpf_attr attr = {};
    struct bpf_map *alloc_map;

    qs->map.ops = 0;
    qs->map.key_size = 0;
    qs->map.value_size = sizeof(u64);
    qs->map.max_entries = 3;
    qs->map.map_flags = 0;
    qs->map.numa_node = 0;
    raw_res_spin_lock_init(&qs->lock);
    qs->head = 0;
    qs->tail = 0;
    qs->size = 4;

    BPF_ASSERT(queue_stack_map_is_empty(qs));
    BPF_ASSERT(!queue_stack_map_is_full(qs));
    BPF_ASSERT(queue_stack_map_mem_usage(map) ==
               sizeof(struct bpf_queue_stack) + 32);

    BPF_ASSERT(queue_stack_map_push_elem(map, &in0, 0) == 0);
    BPF_ASSERT(queue_stack_map_push_elem(map, &in1, 0) == 0);
    BPF_ASSERT(queue_map_peek_elem(map, &out) == 0);
    BPF_ASSERT(out == in0);
    BPF_ASSERT(queue_map_pop_elem(map, &out) == 0);
    BPF_ASSERT(out == in0);
    BPF_ASSERT(queue_map_pop_elem(map, &out) == 0);
    BPF_ASSERT(out == in1);
    BPF_ASSERT(queue_map_pop_elem(map, &out) == -ENOENT);
    BPF_ASSERT(out == 0);

    qs->map.value_size = sizeof(u64);
    qs->map.max_entries = 3;
    qs->head = 0;
    qs->tail = 0;
    qs->size = 4;
    BPF_ASSERT(queue_stack_map_push_elem(map, &in0, 0) == 0);
    BPF_ASSERT(queue_stack_map_push_elem(map, &in1, 0) == 0);
    BPF_ASSERT(queue_stack_map_push_elem(map, &in2, 0) == 0);
    BPF_ASSERT(queue_stack_map_is_full(qs));
    BPF_ASSERT(queue_stack_map_push_elem(map, &in3, 0) == -E2BIG);
    BPF_ASSERT(queue_stack_map_push_elem(map, &in3, BPF_EXIST) == 0);
    BPF_ASSERT(stack_map_peek_elem(map, &out) == 0);
    BPF_ASSERT(out == in3);
    BPF_ASSERT(stack_map_pop_elem(map, &out) == 0);
    BPF_ASSERT(out == in3);
    BPF_ASSERT(queue_stack_map_push_elem(map, &in0, BPF_NOEXIST) == -EINVAL);
    BPF_ASSERT(queue_stack_map_update_elem(map, 0, &in0, 0) == -EINVAL);
    BPF_ASSERT(queue_stack_map_delete_elem(map, 0) == -EINVAL);
    BPF_ASSERT(queue_stack_map_get_next_key(map, 0, 0) == -EINVAL);
    BPF_ASSERT(queue_stack_map_lookup_elem(map, 0) == 0);

    attr.max_entries = 3;
    attr.value_size = sizeof(u64);
    BPF_ASSERT(queue_stack_map_alloc_check(&attr) == 0);
    __bpf_qs_allocated = 0;
    alloc_map = queue_stack_map_alloc(&attr);
    BPF_ASSERT(alloc_map == &__bpf_qs_alloc.qs.map);
    BPF_ASSERT(__bpf_qs_alloc.qs.size == 4);
    queue_stack_map_free(alloc_map);
    BPF_ASSERT(__bpf_qs_allocated == 0);

    attr.key_size = 1;
    BPF_ASSERT(queue_stack_map_alloc_check(&attr) == -EINVAL);
    return (int)out;