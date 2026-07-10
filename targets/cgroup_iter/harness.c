    /* cgroup_iter: cgroup attach validation, seq traversal, fdinfo/link-info,
     * and css kfunc iterator state. */
    struct cgroup_iter_priv priv = {};
    struct seq_file seq = { .private = &priv };
    struct seq_file fdseq = {};
    union bpf_iter_link_info linfo = {};
    struct bpf_iter_aux_info aux = {};
    struct bpf_link_info link_info = {};
    struct bpf_iter_css css_it = {};
    struct cgroup_subsys_state *css;
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0;
    u32 order = BPF_CGROUP_ITER_DESCENDANTS_PRE + (seed & 1);
    loff_t pos = 1;
    void *v;
    void *next = NULL;
    u32 errors = 0;

    __bpf_iter_cgroup_reset();
    linfo.cgroup.order = 99;
    errors |= bpf_iter_attach_cgroup(NULL, &linfo, &aux) != -EINVAL;
    linfo.cgroup.order = order;
    linfo.cgroup.cgroup_fd = 1;
    linfo.cgroup.cgroup_id = 10;
    errors |= bpf_iter_attach_cgroup(NULL, &linfo, &aux) != -EINVAL;

    aux.cgroup.start = &__bpf_iter_cgroup_root;
    aux.cgroup.order = order;

    errors |= cgroup_iter_seq_init(&priv, &aux) != 0;
    v = cgroup_iter_seq_start(&seq, &pos);
    errors |= !IS_ERR(v);
    cgroup_iter_seq_stop(&seq, v);

    pos = 0;
    v = cgroup_iter_seq_start(&seq, &pos);
    if (v && !IS_ERR(v)) {
        next = cgroup_iter_seq_next(&seq, v, &pos);
        cgroup_iter_seq_stop(&seq, NULL);
    } else {
        errors |= 1;
        cgroup_iter_seq_stop(&seq, NULL);
    }
    cgroup_iter_seq_fini(&priv);

    bpf_iter_cgroup_show_fdinfo(&aux, &fdseq);
    errors |= fdseq.writes == 0;
    errors |= bpf_iter_cgroup_fill_link_info(&aux, &link_info) != 0;
    errors |= link_info.iter.cgroup.order != order;
    errors |= link_info.iter.cgroup.cgroup_id == 0;
    bpf_iter_detach_cgroup(&aux);

    errors |= bpf_iter_css_new(&css_it, &__bpf_iter_cgroup_root.self, 99) != -EINVAL;
    errors |= bpf_iter_css_new(&css_it, &__bpf_iter_cgroup_root.self, order) != 0;
    css = bpf_iter_css_next(&css_it);
    errors |= css == NULL;
    css = bpf_iter_css_next(&css_it);
    bpf_iter_css_destroy(&css_it);

    errors |= bpf_cgroup_iter_init() != 0;

    return (int)(errors + __bpf_iter_runs + __bpf_iter_regs +
                 __bpf_iter_cgroup_locks + __bpf_iter_cgroup_unlocks +
                 __bpf_iter_cgroup_css_gets + __bpf_iter_cgroup_css_puts +
                 __bpf_iter_cgroup_puts + fdseq.writes + pos +
                 (next != NULL) + (css != NULL) + (seed & 1));
