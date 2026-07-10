    /* tcx_prove: verifier-enforced TCX guard and link invariants.
     *
     * The TCX shim keeps mprog attach/detach intentionally focused, so this
     * proof targets TCX-facing return codes, link-update guards, and link
     * metadata/fdinfo behavior instead of mprog revision matching.
     */
    union bpf_attr attr = {};
    union bpf_attr uattr = {};
    struct bpf_link_info info = {};
    struct seq_file seq = {};
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0;

    __bpf_tcx_reset();
    attr.attach_type = BPF_TCX_INGRESS;
    attr.target_ifindex = 9;
    BPF_PROVE(tcx_prog_attach(&attr, &__bpf_mprog_prog0) == -ENODEV);
    BPF_PROVE(tcx_prog_detach(&attr, &__bpf_mprog_prog0) == -ENODEV);
    attr.query.attach_type = BPF_TCX_INGRESS;
    attr.query.target_ifindex = 9;
    BPF_PROVE(tcx_prog_query(&attr, &uattr) == -ENODEV);
    attr.link_create.attach_type = BPF_TCX_INGRESS;
    attr.link_create.target_ifindex = 9;
    BPF_PROVE(tcx_link_attach(&attr, &__bpf_mprog_prog0) == -ENODEV);

    __bpf_tcx_reset();
    attr.query.attach_type = BPF_TCX_INGRESS;
    attr.query.target_ifindex = 1;
    BPF_PROVE(tcx_prog_query(&attr, &uattr) == 0);
    attr.attach_type = BPF_TCX_INGRESS;
    attr.target_ifindex = 1;
    BPF_PROVE(tcx_prog_detach(&attr, &__bpf_mprog_prog0) == -ENOENT);
    BPF_PROVE(tcx_prog_attach(&attr, &__bpf_mprog_prog0) == 0);
    attr.query.attach_type = BPF_TCX_INGRESS;
    attr.query.target_ifindex = 1;
    BPF_PROVE(tcx_prog_query(&attr, &uattr) == 0);

    __bpf_tcx_reset();
    __bpf_tcx_link0.dev = NULL;
    __bpf_tcx_link0.link.prog = &__bpf_mprog_prog0;
    __bpf_tcx_link0.link.attach_type = BPF_TCX_INGRESS;
    BPF_PROVE(tcx_link_update(&__bpf_tcx_link0.link, &__bpf_mprog_prog1,
                              &__bpf_mprog_prog0) == -ENOLINK);
    __bpf_tcx_link0.dev = &__bpf_tcx_dev;
    BPF_PROVE(tcx_link_update(&__bpf_tcx_link0.link, &__bpf_mprog_prog1,
                              &__bpf_mprog_prog2) == -EPERM);
    BPF_PROVE(tcx_link_update(&__bpf_tcx_link0.link, &__bpf_mprog_prog0,
                              &__bpf_mprog_prog0) == 0);

    __bpf_tcx_reset();
    __bpf_tcx_link0.dev = &__bpf_tcx_dev;
    __bpf_tcx_link0.link.attach_type = BPF_TCX_INGRESS;
    BPF_PROVE(tcx_link_fill_info(&__bpf_tcx_link0.link, &info) == 0);
    BPF_PROVE(info.tcx.ifindex == 1);
    BPF_PROVE(info.tcx.attach_type == BPF_TCX_INGRESS);
    tcx_link_fdinfo(&__bpf_tcx_link0.link, &seq);
    BPF_PROVE(seq.writes == 2);

    __bpf_tcx_reset();
    attr.link_create.attach_type = BPF_TCX_INGRESS;
    attr.link_create.target_ifindex = 1;
    attr.link_create.flags = 0;
    attr.link_create.tcx.relative_fd = 0;
    attr.link_create.tcx.expected_revision = 0;
    BPF_PROVE(tcx_link_attach(&attr, &__bpf_mprog_prog1) == 7);
    BPF_PROVE(__bpf_tcx_link0.link.id == 200);
    BPF_PROVE(__bpf_tcx_link0.link.type == BPF_LINK_TYPE_TCX);
    BPF_PROVE(__bpf_tcx_link0.link.attach_type == BPF_TCX_INGRESS);
    BPF_PROVE(tcx_link_detach(&__bpf_tcx_link0.link) == 0);

    return (int)(seed & 1);
