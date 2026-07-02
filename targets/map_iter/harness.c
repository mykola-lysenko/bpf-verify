    /* map_iter: sequence operations, map attach validation, fdinfo/link-info,
     * and the element-count kfunc. */
    struct bpf_iter_seq_map_info seq_info = {};
    struct seq_file seq = { .private = &seq_info };
    struct seq_file fdseq = {};
    struct bpf_prog_aux aux_cfg = {
        .max_rdonly_access = 4,
        .max_rdwr_access = 8,
    };
    struct bpf_prog prog = { .aux = &aux_cfg };
    union bpf_iter_link_info linfo = {};
    struct bpf_iter_aux_info aux = {};
    struct bpf_link_info link_info = {};
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0;
    loff_t pos = 0;
    void *v;
    void *next = NULL;
    s64 sum;
    int rc;
    u32 errors = 0;

    seq_info.map_id = seed & 3;
    pos = seed & 1;
    __bpf_iter_reset();
    v = bpf_map_seq_start(&seq, &pos);
    if (v) {
        errors |= bpf_map_seq_show(&seq, v) != 7;
        next = bpf_map_seq_next(&seq, v, &pos);
        bpf_map_seq_stop(&seq, next);
    } else {
        bpf_map_seq_stop(&seq, NULL);
    }

    errors |= bpf_iter_attach_map(&prog, &linfo, &aux) != -EBADF;
    linfo.map.map_fd = 1;
    __bpf_iter_map0.map_type = (seed & 2) ? BPF_MAP_TYPE_PERCPU_ARRAY :
                                           BPF_MAP_TYPE_HASH;
    __bpf_iter_map0.key_size = 4 + (seed & 3);
    __bpf_iter_map0.value_size = 8;
    __bpf_iter_map0.id = 1234;
    aux_cfg.max_rdonly_access = 1 + (seed & 3);
    aux_cfg.max_rdwr_access = 1 + (seed & 7);
    rc = bpf_iter_attach_map(&prog, &linfo, &aux);
    errors |= rc != 0;
    if (!rc) {
        errors |= aux.map != &__bpf_iter_map0;
        bpf_iter_map_show_fdinfo(&aux, &fdseq);
        errors |= bpf_iter_map_fill_link_info(&aux, &link_info) != 0;
        errors |= link_info.iter.map.map_id != 1234;
        bpf_iter_detach_map(&aux);
    }

    aux_cfg.max_rdwr_access = 32;
    __bpf_iter_map0.map_type = BPF_MAP_TYPE_HASH;
    __bpf_iter_map0.key_size = 4;
    __bpf_iter_map0.value_size = 8;
    errors |= bpf_iter_attach_map(&prog, &linfo, &aux) != -EACCES;
    aux_cfg.max_rdwr_access = 8;
    __bpf_iter_map0.map_type = BPF_MAP_TYPE_PERCPU_ARRAY;
    __bpf_iter_map0.value_size = 4;
    errors |= bpf_iter_attach_map(&prog, &linfo, &aux) != 0;
    bpf_iter_detach_map(&aux);
    __bpf_iter_map0.map_type = 999;
    errors |= bpf_iter_attach_map(&prog, &linfo, &aux) != -EINVAL;

    __bpf_iter_map0.elem_count = __bpf_iter_elem_counts;
    __bpf_iter_elem_counts[0] = (s64)(1 + (seed & 7));
    __bpf_iter_elem_counts[1] = (s64)(1 + ((seed >> 3) & 7));
    sum = bpf_map_sum_elem_count(&__bpf_iter_map0);
    errors |= sum <= 0;
    __bpf_iter_map0.elem_count = NULL;
    errors |= bpf_map_sum_elem_count(&__bpf_iter_map0) != 0;
    errors |= bpf_map_sum_elem_count(NULL) != 0;

    errors |= bpf_map_iter_init() != 0;
    errors |= init_subsystem() != 0;

    return (int)(errors + __bpf_iter_runs + __bpf_iter_map_puts +
                 __bpf_iter_map_puts_uref + __bpf_iter_regs +
                 __bpf_iter_kfunc_regs + seq_info.map_id + pos +
                 (v != NULL) + (next != NULL) + fdseq.writes +
                 (u64)sum + (seed & 1));