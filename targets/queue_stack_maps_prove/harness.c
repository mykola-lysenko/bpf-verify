    /* queue_stack_maps_prove: verifier-enforced queue/stack invariants.
     *
     * A symbolic branch selects queue or stack mode so the verifier checks
     * both independently:
     *   1. Queue FIFO preserves full/empty state and rejects over-capacity push.
     *   2. Stack BPF_EXIST replacement preserves capacity and pops LIFO order.
     */
    __u32 key = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &key);
    if (!vp) return 0;

    if (*vp & 1) {
        struct {
            struct bpf_queue_stack qs;
            u8 data[32];
        } storage = {};
        struct bpf_queue_stack *qs = &storage.qs;
        struct bpf_map *map = &qs->map;
        u64 in0 = 0x1111111111111111ULL;
        u64 in1 = 0x2222222222222222ULL;
        u64 in2 = 0x3333333333333333ULL;
        u64 in3 = 0x4444444444444444ULL;
        u64 out = 0;

        qs->map.value_size = sizeof(u64);
        qs->map.max_entries = 3;
        raw_res_spin_lock_init(&qs->lock);
        qs->head = 0;
        qs->tail = 0;
        qs->size = 4;

        BPF_PROVE(queue_stack_map_is_empty(qs));
        BPF_PROVE(!queue_stack_map_is_full(qs));
        BPF_PROVE(queue_stack_map_mem_usage(map) ==
                  sizeof(struct bpf_queue_stack) + 32);
        BPF_PROVE(queue_stack_map_push_elem(map, &in0, 0) == 0);
        BPF_PROVE(qs->head == 1 && qs->tail == 0);
        BPF_PROVE(!queue_stack_map_is_empty(qs));
        BPF_PROVE(!queue_stack_map_is_full(qs));
        BPF_PROVE(queue_stack_map_push_elem(map, &in1, 0) == 0);
        BPF_PROVE(qs->head == 2 && qs->tail == 0);
        BPF_PROVE(queue_stack_map_push_elem(map, &in2, 0) == 0);
        BPF_PROVE(qs->head == 3 && qs->tail == 0);
        BPF_PROVE(queue_stack_map_is_full(qs));
        BPF_PROVE(queue_stack_map_push_elem(map, &in3, 0) == -E2BIG);
        BPF_PROVE(qs->head == 3 && qs->tail == 0);
        BPF_PROVE(queue_map_peek_elem(map, &out) == 0);
        BPF_PROVE(out == in0);
        BPF_PROVE(qs->tail == 0);
        out = 0;
        BPF_PROVE(queue_map_pop_elem(map, &out) == 0);
        BPF_PROVE(out == in0);
        BPF_PROVE(qs->head == 3 && qs->tail == 1);
        BPF_PROVE(!queue_stack_map_is_full(qs));
        out = 0;
        BPF_PROVE(queue_map_pop_elem(map, &out) == 0);
        BPF_PROVE(out == in1);
        out = 0;
        BPF_PROVE(queue_map_pop_elem(map, &out) == 0);
        BPF_PROVE(out == in2);
        BPF_PROVE(queue_stack_map_is_empty(qs));
        out = 0xdeadbeefULL;
        BPF_PROVE(queue_map_pop_elem(map, &out) == -ENOENT);
        BPF_PROVE(out == 0);
        return (int)out;
    } else {
        struct {
            struct bpf_queue_stack qs;
            u8 data[32];
        } storage = {};
        struct bpf_queue_stack *qs = &storage.qs;
        struct bpf_map *map = &qs->map;
        u64 seed = *vp;
        u64 in0 = seed;
        u64 in1 = seed ^ 0x1111111111111111ULL;
        u64 in2 = seed ^ 0x2222222222222222ULL;
        u64 in3 = seed ^ 0x3333333333333333ULL;
        u64 out = 0;

        qs->map.value_size = sizeof(u64);
        qs->map.max_entries = 3;
        raw_res_spin_lock_init(&qs->lock);
        qs->head = 0;
        qs->tail = 0;
        qs->size = 4;

        BPF_PROVE(queue_stack_map_push_elem(map, &in0, 0) == 0);
        BPF_PROVE(queue_stack_map_push_elem(map, &in1, 0) == 0);
        BPF_PROVE(queue_stack_map_push_elem(map, &in2, 0) == 0);
        BPF_PROVE(queue_stack_map_is_full(qs));
        BPF_PROVE(queue_stack_map_push_elem(map, &in3, BPF_EXIST) == 0);
        BPF_PROVE(qs->head == 0 && qs->tail == 1);
        BPF_PROVE(queue_stack_map_is_full(qs));
        BPF_PROVE(stack_map_peek_elem(map, &out) == 0);
        BPF_PROVE(out == in3);
        BPF_PROVE(qs->head == 0 && qs->tail == 1);
        out = 0;
        BPF_PROVE(stack_map_pop_elem(map, &out) == 0);
        BPF_PROVE(out == in3);
        BPF_PROVE(qs->head == 3 && qs->tail == 1);
        BPF_PROVE(!queue_stack_map_is_full(qs));
        out = 0;
        BPF_PROVE(stack_map_pop_elem(map, &out) == 0);
        BPF_PROVE(out == in2);
        out = 0;
        BPF_PROVE(stack_map_pop_elem(map, &out) == 0);
        BPF_PROVE(out == in1);
        BPF_PROVE(queue_stack_map_is_empty(qs));
        out = 0xdeadbeefULL;
        BPF_PROVE(stack_map_pop_elem(map, &out) == -ENOENT);
        BPF_PROVE(out == 0);
        return (int)(out ^ seed);
    }
