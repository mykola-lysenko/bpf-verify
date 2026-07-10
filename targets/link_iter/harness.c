    /* link_iter: BPF link iterator sequence operations and registration. */
    struct bpf_iter_seq_link_info info = {};
    struct seq_file seq = { .private = &info };
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0;
    loff_t pos = 0;
    void *v;
    void *next;
    u32 errors = 0;

    info.link_id = seed & 3;
    pos = seed & 1;
    next = NULL;
    __bpf_iter_reset();
    v = bpf_link_seq_start(&seq, &pos);
    if (v) {
        errors |= bpf_link_seq_show(&seq, v) != 7;
        next = bpf_link_seq_next(&seq, v, &pos);
        bpf_link_seq_stop(&seq, next);
    } else {
        bpf_link_seq_stop(&seq, NULL);
    }
    errors |= bpf_link_iter_init() != 0;

    return (int)(errors + __bpf_iter_runs + __bpf_iter_link_puts +
                 __bpf_iter_regs + info.link_id + pos + (v != NULL) +
                 (next != NULL) + (seed & 1));
