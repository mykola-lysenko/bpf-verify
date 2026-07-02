    /* tcx: netdevice attach/detach/query, link attach/release, and
     * uninstall cleanup on top of the focused mprog shim below. */
    union bpf_attr attr = {};
    union bpf_attr uattr = {};
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0;
    int ret;
    u32 errors = 0;

    __bpf_tcx_reset();
    attr.attach_type = BPF_TCX_INGRESS;
    attr.target_ifindex = 1;
    errors |= tcx_prog_attach(&attr, &__bpf_mprog_prog0) != 0;

    attr.query.attach_type = BPF_TCX_INGRESS;
    attr.query.target_ifindex = 1;
    attr.query.count = 0;
    errors |= tcx_prog_query(&attr, &uattr) != 0;

    attr.attach_type = BPF_TCX_INGRESS;
    attr.target_ifindex = 1;
    errors |= tcx_prog_detach(&attr, &__bpf_mprog_prog0) != 0;

    attr.target_ifindex = 9;
    errors |= tcx_prog_attach(&attr, &__bpf_mprog_prog0) != -ENODEV;

    attr.link_create.attach_type = BPF_TCX_INGRESS;
    attr.link_create.target_ifindex = 1;
    attr.link_create.flags = 0;
    attr.link_create.tcx.relative_fd = 0;
    attr.link_create.tcx.expected_revision = 0;
    ret = tcx_link_attach(&attr, &__bpf_mprog_prog1);
    errors |= ret != 7;
    errors |= __bpf_tcx_link0.dev != &__bpf_tcx_dev;

    errors |= tcx_link_detach(&__bpf_tcx_link0.link) != 0;
    errors |= __bpf_tcx_link0.dev != NULL;

    attr.attach_type = BPF_TCX_EGRESS;
    attr.target_ifindex = 1;
    errors |= tcx_prog_attach(&attr, &__bpf_mprog_prog3) != 0;
    tcx_uninstall(&__bpf_tcx_dev, false);
    errors |= __bpf_tcx_dev.tcx_egress != NULL;

    return (int)(errors + __bpf_tcx_locks + __bpf_tcx_unlocks +
                 __bpf_tcx_syncs + __bpf_tcx_skey_inc +
                 __bpf_tcx_skey_dec + __bpf_tcx_link_settles +
                 __bpf_mprog_prog_puts + (seed & 1));