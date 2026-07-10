    /* syscall_attach_link_prove: attach-type routing, load-time attach
     * guards, and link initialization invariants from kernel/bpf/syscall.c. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    __u64 choice = input ? *input : 0;
    union bpf_attr attr = {};
    struct btf btf = { .id = 1 };
    struct bpf_token no_caps = {};
    struct bpf_token net_admin = { .cap_net_admin = true };
    struct bpf_token sys_admin = {
        .cap_net_admin = true,
        .cap_sys_admin = true,
    };
    struct bpf_prog_aux aux = { .token = &no_caps };
    struct bpf_prog prog = { .aux = &aux };
    struct bpf_prog dst_prog = {};
    struct bpf_link_ops ops = {};
    struct bpf_link link = {};
    struct bpf_tramp_link tramp = {};
    int ret;
    int acc = 0;

    attr.prog_type = BPF_PROG_TYPE_CGROUP_SOCK;
    attr.expected_attach_type = 0;
    bpf_prog_load_fixup_attach_type(&attr);
    BPF_PROVE(attr.expected_attach_type == BPF_CGROUP_INET_SOCK_CREATE);

    attr.prog_type = BPF_PROG_TYPE_CGROUP_SOCK;
    attr.expected_attach_type = BPF_CGROUP_INET_SOCK_RELEASE;
    bpf_prog_load_fixup_attach_type(&attr);
    BPF_PROVE(attr.expected_attach_type == BPF_CGROUP_INET_SOCK_RELEASE);

    attr.prog_type = BPF_PROG_TYPE_SK_REUSEPORT;
    attr.expected_attach_type = 0;
    bpf_prog_load_fixup_attach_type(&attr);
    BPF_PROVE(attr.expected_attach_type == BPF_SK_REUSEPORT_SELECT);

    ret = bpf_prog_load_check_attach(BPF_PROG_TYPE_TRACING,
                                     BPF_TRACE_FENTRY, &btf, 1, NULL, false);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = bpf_prog_load_check_attach(BPF_PROG_TYPE_XDP,
                                     BPF_TRACE_FENTRY, &btf, 1, NULL, false);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    ret = bpf_prog_load_check_attach(BPF_PROG_TYPE_TRACING,
                                     BPF_TRACE_FENTRY, NULL, 1, NULL, false);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    ret = bpf_prog_load_check_attach(BPF_PROG_TYPE_TRACING,
                                     BPF_TRACE_FENTRY, &btf,
                                     BTF_MAX_TYPE + 1, NULL, false);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    ret = bpf_prog_load_check_attach(BPF_PROG_TYPE_TRACING,
                                     BPF_TRACE_FENTRY, &btf, 0, NULL, true);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = bpf_prog_load_check_attach(BPF_PROG_TYPE_LSM,
                                     BPF_LSM_MAC, &btf, 0, NULL, true);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    ret = bpf_prog_load_check_attach(BPF_PROG_TYPE_TRACING,
                                     BPF_TRACE_FENTRY, NULL, 0, NULL, true);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    ret = bpf_prog_load_check_attach(BPF_PROG_TYPE_TRACING,
                                     BPF_TRACE_FENTRY, &btf, 1, NULL, true);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    ret = bpf_prog_load_check_attach(BPF_PROG_TYPE_CGROUP_SOCK,
                                     BPF_CGROUP_INET_SOCK_CREATE, NULL, 0,
                                     NULL, false);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = bpf_prog_load_check_attach(BPF_PROG_TYPE_CGROUP_SOCK,
                                     BPF_CGROUP_INET_INGRESS, NULL, 0,
                                     NULL, false);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    ret = bpf_prog_load_check_attach(BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                                     BPF_CGROUP_UNIX_RECVMSG, NULL, 0,
                                     NULL, false);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = bpf_prog_load_check_attach(BPF_PROG_TYPE_CGROUP_SOCKOPT,
                                     BPF_CGROUP_GETSOCKOPT, NULL, 0,
                                     NULL, false);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = bpf_prog_load_check_attach(BPF_PROG_TYPE_SK_LOOKUP,
                                     BPF_SK_LOOKUP, NULL, 0, NULL, false);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = bpf_prog_load_check_attach(BPF_PROG_TYPE_SK_REUSEPORT,
                                     BPF_SK_REUSEPORT_SELECT_OR_MIGRATE,
                                     NULL, 0, NULL, false);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = bpf_prog_load_check_attach(BPF_PROG_TYPE_NETFILTER,
                                     BPF_XDP, NULL, 0, NULL, false);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    ret = bpf_prog_load_check_attach(BPF_PROG_TYPE_SYSCALL,
                                     BPF_XDP, NULL, 0, NULL, false);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    ret = bpf_prog_load_check_attach(BPF_PROG_TYPE_EXT,
                                     BPF_XDP, NULL, 0, NULL, false);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    ret = bpf_prog_load_check_attach(BPF_PROG_TYPE_EXT,
                                     0, NULL, 0, &dst_prog, false);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = bpf_prog_load_check_attach(BPF_PROG_TYPE_XDP,
                                     0, NULL, 0, &dst_prog, false);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    BPF_PROVE(attach_type_to_prog_type(BPF_CGROUP_INET_INGRESS) ==
              BPF_PROG_TYPE_CGROUP_SKB);
    BPF_PROVE(attach_type_to_prog_type(BPF_CGROUP_UNIX_SENDMSG) ==
              BPF_PROG_TYPE_CGROUP_SOCK_ADDR);
    BPF_PROVE(attach_type_to_prog_type(BPF_TRACE_FSESSION_MULTI) ==
              BPF_PROG_TYPE_TRACING);
    BPF_PROVE(attach_type_to_prog_type(BPF_NETKIT_PEER) ==
              BPF_PROG_TYPE_SCHED_CLS);
    BPF_PROVE(attach_type_to_prog_type(__MAX_BPF_ATTACH_TYPE) ==
              BPF_PROG_TYPE_UNSPEC);

    prog.type = BPF_PROG_TYPE_CGROUP_SOCK;
    prog.expected_attach_type = BPF_CGROUP_INET_SOCK_CREATE;
    ret = bpf_prog_attach_check_attach_type(&prog,
                                            BPF_CGROUP_INET_SOCK_CREATE);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = bpf_prog_attach_check_attach_type(&prog,
                                            BPF_CGROUP_INET_SOCK_RELEASE);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    prog.type = BPF_PROG_TYPE_CGROUP_SKB;
    prog.expected_attach_type = BPF_CGROUP_INET_EGRESS;
    prog.enforce_expected_attach_type = false;
    aux.token = &no_caps;
    ret = bpf_prog_attach_check_attach_type(&prog, BPF_CGROUP_INET_INGRESS);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EPERM);
    aux.token = &net_admin;
    ret = bpf_prog_attach_check_attach_type(&prog, BPF_CGROUP_INET_INGRESS);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    prog.enforce_expected_attach_type = true;
    ret = bpf_prog_attach_check_attach_type(&prog, BPF_CGROUP_INET_INGRESS);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    ret = bpf_prog_attach_check_attach_type(&prog, BPF_CGROUP_INET_EGRESS);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    aux.token = &sys_admin;
    ret = bpf_prog_attach_check_attach_type(&prog, BPF_CGROUP_INET_EGRESS);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);

    prog.type = BPF_PROG_TYPE_NETFILTER;
    prog.expected_attach_type = BPF_NETFILTER;
    ret = bpf_prog_attach_check_attach_type(&prog, BPF_NETFILTER);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = bpf_prog_attach_check_attach_type(&prog, BPF_XDP);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    prog.type = BPF_PROG_TYPE_KPROBE;
    prog.expected_attach_type = BPF_TRACE_KPROBE_MULTI;
    ret = bpf_prog_attach_check_attach_type(&prog, BPF_TRACE_KPROBE_MULTI);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = bpf_prog_attach_check_attach_type(&prog, BPF_PERF_EVENT);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    prog.type = BPF_PROG_TYPE_TRACEPOINT;
    ret = bpf_prog_attach_check_attach_type(&prog, BPF_PERF_EVENT);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = bpf_prog_attach_check_attach_type(&prog, BPF_TRACE_RAW_TP);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    prog.type = BPF_PROG_TYPE_SCHED_CLS;
    ret = bpf_prog_attach_check_attach_type(&prog, BPF_NETKIT_PRIMARY);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = bpf_prog_attach_check_attach_type(&prog, BPF_XDP);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    prog.type = BPF_PROG_TYPE_SK_MSG;
    ret = bpf_prog_attach_check_attach_type(&prog, BPF_SK_MSG_VERDICT);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = bpf_prog_attach_check_attach_type(&prog, BPF_XDP);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    BPF_PROVE(is_cgroup_prog_type(BPF_PROG_TYPE_CGROUP_SKB, BPF_XDP, true));
    BPF_PROVE(is_cgroup_prog_type(BPF_PROG_TYPE_LSM, BPF_LSM_CGROUP, true));
    BPF_PROVE(is_cgroup_prog_type(BPF_PROG_TYPE_LSM, BPF_XDP, false));
    BPF_PROVE(!is_cgroup_prog_type(BPF_PROG_TYPE_LSM, BPF_XDP, true));
    BPF_PROVE(!is_cgroup_prog_type(BPF_PROG_TYPE_XDP, BPF_XDP, true));

    bpf_link_init_sleepable(&link, BPF_LINK_TYPE_TRACING, &ops, &prog,
                            BPF_TRACE_FENTRY, true);
    BPF_PROVE(link.refcnt.counter == 1);
    BPF_PROVE(link.type == BPF_LINK_TYPE_TRACING);
    BPF_PROVE(link.sleepable);
    BPF_PROVE(link.id == 0);
    BPF_ASSERT(link.ops == &ops);
    BPF_ASSERT(link.prog == &prog);
    BPF_PROVE(link.attach_type == BPF_TRACE_FENTRY);

    bpf_link_init(&link, BPF_LINK_TYPE_TCX, &ops, &prog, BPF_TCX_EGRESS);
    BPF_PROVE(link.refcnt.counter == 1);
    BPF_PROVE(link.type == BPF_LINK_TYPE_TCX);
    BPF_PROVE(!link.sleepable);
    BPF_ASSERT(link.ops == &ops);
    BPF_ASSERT(link.prog == &prog);
    BPF_PROVE(link.attach_type == BPF_TCX_EGRESS);

    bpf_tramp_link_init(&tramp, BPF_LINK_TYPE_TRACING, &ops, &prog,
                        BPF_TRACE_FEXIT, 0x1234);
    BPF_PROVE(tramp.link.refcnt.counter == 1);
    BPF_PROVE(tramp.link.type == BPF_LINK_TYPE_TRACING);
    BPF_PROVE(!tramp.link.sleepable);
    BPF_ASSERT(tramp.link.ops == &ops);
    BPF_ASSERT(tramp.link.prog == &prog);
    BPF_PROVE(tramp.link.attach_type == BPF_TRACE_FEXIT);
    BPF_ASSERT(tramp.node.link == &tramp.link);
    BPF_PROVE(tramp.node.cookie == 0x1234);

    acc += ret + (int)choice + (int)attr.expected_attach_type;
    return acc;
