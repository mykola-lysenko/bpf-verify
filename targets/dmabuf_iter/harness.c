    /* dmabuf_iter: sequence resume/drop behavior, registration, and kfunc
     * iterator state transitions. */
    struct dmabuf_iter_priv priv = {};
    struct seq_file seq = { .private = &priv };
    struct seq_file fdseq = {};
    struct bpf_iter_dmabuf iter = {};
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0;
    loff_t pos = 0;
    void *v;
    void *next = NULL;
    u32 errors = 0;

    __bpf_iter_reset();
    errors |= dmabuf_iter_seq_init(&priv, NULL) != 0;
    pos = seed & 1;
    if (pos && (seed & 2))
        priv.dmabuf = &__bpf_iter_dmabuf1;
    v = dmabuf_iter_seq_start(&seq, &pos);
    if (v) {
        errors |= dmabuf_iter_seq_show(&seq, v) != 7;
        next = dmabuf_iter_seq_next(&seq, v, &pos);
        dmabuf_iter_seq_stop(&seq, next ? next : v);
    }
    dmabuf_iter_seq_fini(&priv);

    errors |= bpf_iter_dmabuf_new(&iter) != 0;
    errors |= bpf_iter_dmabuf_next(&iter) != &__bpf_iter_dmabuf0;
    errors |= bpf_iter_dmabuf_next(&iter) != &__bpf_iter_dmabuf1;
    bpf_iter_dmabuf_destroy(&iter);

    bpf_iter_dmabuf_show_fdinfo(NULL, &fdseq);
    errors |= dmabuf_iter_init() != 0;

    return (int)(errors + __bpf_iter_runs + __bpf_iter_dmabuf_puts +
                 __bpf_iter_regs + fdseq.writes + pos + (v != NULL) +
                 (next != NULL) + (seed & 1));