    /* kmem_cache_iter: list-backed seq traversal, kfunc iterator refcount
     * transitions, stop-path handling, fdinfo, and registration. */
    struct bpf_iter_kmem_cache it = {};
    union kmem_cache_iter_priv priv = {};
    struct seq_file seq = { .private = &priv };
    struct seq_file fdseq = {};
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0;
    loff_t pos = seed & 1;
    void *v;
    void *next = NULL;
    u32 errors = 0;

    __bpf_iter_kmem_reset();
    errors |= bpf_iter_kmem_cache_new(&it) != 0;
    v = bpf_iter_kmem_cache_next(&it);
    errors |= v != &__bpf_iter_kmem0;
    next = bpf_iter_kmem_cache_next(&it);
    errors |= next != &__bpf_iter_kmem1;
    bpf_iter_kmem_cache_destroy(&it);

    v = kmem_cache_iter_seq_start(&seq, &pos);
    if (v) {
        errors |= kmem_cache_iter_seq_show(&seq, v) != 7;
        next = kmem_cache_iter_seq_next(&seq, v, &pos);
        kmem_cache_iter_seq_stop(&seq, next ? next : v);
    } else {
        kmem_cache_iter_seq_stop(&seq, NULL);
    }
    priv.kit.pos = NULL;
    kmem_cache_iter_seq_stop(&seq, NULL);

    bpf_iter_kmem_cache_show_fdinfo(NULL, &fdseq);
    errors |= fdseq.writes != 1;
    errors |= bpf_kmem_cache_iter_init() != 0;

    return (int)(errors + __bpf_iter_runs + __bpf_iter_regs +
                 __bpf_iter_kmem_destroys + fdseq.writes + pos +
                 (v != NULL) + (next != NULL) + (seed & 1));
