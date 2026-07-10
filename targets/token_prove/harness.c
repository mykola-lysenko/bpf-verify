    /* token_prove: verifier-enforced BPF-token permission invariants. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    __u64 choice = input ? *input : 0;
    struct user_namespace ns = {};
    struct bpf_token token = {};
    bool ok;
    int acc = 0;

    token.userns = &ns;
    token.allowed_cmds = BIT_ULL(BPF_MAP_CREATE);
    token.allowed_maps = BIT_ULL(BPF_MAP_TYPE_ARRAY);
    token.allowed_progs = BIT_ULL(BPF_PROG_TYPE_SOCKET_FILTER);
    token.allowed_attachs = BIT_ULL(BPF_CGROUP_INET_INGRESS);

    BPF_PROVE(!bpf_token_allow_cmd(NULL, BPF_MAP_CREATE));
    ok = bpf_token_allow_cmd(&token, BPF_MAP_CREATE);
    BPF_KEEP_SCALAR(ok);
    BPF_PROVE(ok);
    ok = bpf_token_allow_cmd(&token, BPF_PROG_LOAD);
    BPF_KEEP_SCALAR(ok);
    BPF_PROVE(!ok);

    BPF_PROVE(!bpf_token_allow_map_type(NULL, BPF_MAP_TYPE_ARRAY));
    BPF_PROVE(bpf_token_allow_map_type(&token, BPF_MAP_TYPE_ARRAY));
    BPF_PROVE(!bpf_token_allow_map_type(&token, BPF_MAP_TYPE_HASH));
    BPF_PROVE(!bpf_token_allow_map_type(&token,
                                         (enum bpf_map_type)__MAX_BPF_MAP_TYPE));

    BPF_PROVE(!bpf_token_allow_prog_type(NULL, BPF_PROG_TYPE_SOCKET_FILTER,
                                         BPF_CGROUP_INET_INGRESS));
    BPF_PROVE(bpf_token_allow_prog_type(&token, BPF_PROG_TYPE_SOCKET_FILTER,
                                        BPF_CGROUP_INET_INGRESS));
    BPF_PROVE(!bpf_token_allow_prog_type(&token, BPF_PROG_TYPE_XDP,
                                         BPF_CGROUP_INET_INGRESS));
    BPF_PROVE(!bpf_token_allow_prog_type(&token, BPF_PROG_TYPE_SOCKET_FILTER,
                                         BPF_CGROUP_INET_EGRESS));
    BPF_PROVE(!bpf_token_allow_prog_type(
        &token, (enum bpf_prog_type)__MAX_BPF_PROG_TYPE,
        BPF_CGROUP_INET_INGRESS));
    BPF_PROVE(!bpf_token_allow_prog_type(
        &token, BPF_PROG_TYPE_SOCKET_FILTER,
        (enum bpf_attach_type)__MAX_BPF_ATTACH_TYPE));

    ns.caps = BIT_ULL(CAP_SYS_ADMIN);
    ok = bpf_token_capable(&token, CAP_BPF);
    BPF_KEEP_SCALAR(ok);
    BPF_PROVE(ok);
    ok = bpf_token_capable(&token, CAP_SYS_ADMIN);
    BPF_KEEP_SCALAR(ok);
    BPF_PROVE(ok);

    ns.caps = BIT_ULL(CAP_BPF);
    BPF_PROVE(bpf_token_capable(&token, CAP_BPF));
    BPF_PROVE(!bpf_token_capable(&token, CAP_PERFMON));

    ns.caps = 0;
    BPF_PROVE(!bpf_token_capable(&token, CAP_BPF));

    ns.caps = BIT_ULL(CAP_BPF);
    token.security = &token;
    BPF_PROVE(!bpf_token_capable(&token, CAP_BPF));
    token.security = NULL;

    acc += (int)token.allowed_cmds;
    acc += (choice & 1) ? CAP_BPF : CAP_PERFMON;
    return (int)choice + acc;
