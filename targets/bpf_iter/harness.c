    /* bpf_iter core: open-coded numeric iterator state and bounds. The
     * file/link read path remains compiled but is intentionally not invoked
     * from BPF because it is driven by indirect seq_file callbacks. */
    struct bpf_iter_num it = {};
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0;
    int start = seed & 3;
    int end = start + 1 + ((seed >> 2) & 3);
    int *value;
    int sum = 0;
    u32 i;
    u32 errors = 0;

    __bpf_iter_core_reset();
    errors |= bpf_iter_num_new(&it, end, start) != -EINVAL;
    errors |= bpf_iter_num_new(&it, 0, BPF_MAX_LOOPS + 2) != -E2BIG;
    errors |= bpf_iter_num_new(&it, start, end) != 0;
    for (i = 0; i < 5; i++) {
        value = bpf_iter_num_next(&it);
        if (!value)
            break;
        sum += *value;
    }
    bpf_iter_num_destroy(&it);
    errors |= bpf_iter_num_next(&it) != NULL;

    return (int)(errors + sum + i + __bpf_iter_core_allocs +
                 __bpf_iter_core_frees + (seed & 1));
