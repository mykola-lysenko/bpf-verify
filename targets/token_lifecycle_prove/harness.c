    /* token_lifecycle_prove: token refcount, fd, info, and create guards. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    __u64 choice = input ? *input : 0;
    struct user_namespace ns = {};
    struct bpf_token token = {};
    struct bpf_token *got;
    struct bpf_token_info info = {};
    struct file file = {};
    struct seq_file seq = {};
    union bpf_attr attr = {};
    union bpf_attr out_attr = {};
    int ret;
    int acc = 0;

    __bpf_token_work_scheduled = 0;
    __bpf_token_work_initialized = 0;
    __bpf_token_saw_work = 0;

    token.userns = &ns;
    token.allowed_cmds = BIT_ULL(BPF_MAP_CREATE);
    token.allowed_maps = BIT_ULL(BPF_MAP_TYPE_ARRAY);
    token.allowed_progs = BIT_ULL(BPF_PROG_TYPE_SOCKET_FILTER);
    token.allowed_attachs = BIT_ULL(BPF_CGROUP_INET_INGRESS);
    atomic64_set(&token.refcnt, 2);

    bpf_token_inc(&token);
    BPF_PROVE(token.refcnt.counter == 3);
    bpf_token_put(NULL);
    BPF_ASSERT(__bpf_token_work_scheduled == 0);
    bpf_token_put(&token);
    BPF_PROVE(token.refcnt.counter == 2);
    BPF_ASSERT(__bpf_token_work_scheduled == 0);

    file.private_data = &token;
    ret = bpf_token_release(NULL, &file);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    BPF_PROVE(token.refcnt.counter == 1);
    BPF_ASSERT(__bpf_token_work_scheduled == 0);
    bpf_token_put(&token);
    BPF_PROVE(token.refcnt.counter == 0);
    BPF_ASSERT(__bpf_token_work_initialized == 1);
    BPF_ASSERT(__bpf_token_work_scheduled == 1);
    BPF_ASSERT(__bpf_token_saw_work == 1);
    bpf_token_put_deferred(&token.work);

    file.private_data = &token;
    token.allowed_cmds = BIT_ULL(BPF_MAP_CREATE);
    token.allowed_maps = BIT_ULL(BPF_MAP_TYPE_ARRAY);
    token.allowed_progs = BIT_ULL(BPF_PROG_TYPE_SOCKET_FILTER);
    token.allowed_attachs = BIT_ULL(BPF_CGROUP_INET_INGRESS);
    seq.writes = 0;
    bpf_token_show_fdinfo(&seq, &file);
    BPF_PROVE(seq.writes == 4);
    token.allowed_cmds = ~0ULL;
    token.allowed_maps = ~0ULL;
    token.allowed_progs = ~0ULL;
    token.allowed_attachs = ~0ULL;
    seq.writes = 0;
    bpf_token_show_fdinfo(&seq, &file);
    BPF_PROVE(seq.writes == 4);

    token.allowed_cmds = BIT_ULL(BPF_MAP_CREATE) | BIT_ULL(BPF_PROG_LOAD);
    token.allowed_maps = BIT_ULL(BPF_MAP_TYPE_ARRAY);
    token.allowed_progs = BIT_ULL(BPF_PROG_TYPE_SOCKET_FILTER);
    token.allowed_attachs = BIT_ULL(BPF_CGROUP_INET_INGRESS);
    attr.info.info = (u64)&info;
    attr.info.info_len = sizeof(info);
    out_attr.info.info_len = 0;
    ret = bpf_token_get_info_by_fd(&token, &attr, &out_attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    BPF_ASSERT(info.allowed_cmds == token.allowed_cmds);
    BPF_ASSERT(info.allowed_maps == token.allowed_maps);
    BPF_ASSERT(info.allowed_progs == token.allowed_progs);
    BPF_ASSERT(info.allowed_attachs == token.allowed_attachs);
    BPF_ASSERT(out_attr.info.info_len == sizeof(info));

    attr.info.info = 0;
    attr.info.info_len = sizeof(info);
    ret = bpf_token_get_info_by_fd(&token, &attr, &out_attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EFAULT);

    got = bpf_token_get_from_fd(0);
    BPF_ASSERT(IS_ERR(got));
    BPF_ASSERT(PTR_ERR(got) == -EBADF);

    __bpf_token_file.f_op = NULL;
    got = bpf_token_get_from_fd(1);
    BPF_ASSERT(IS_ERR(got));
    BPF_ASSERT(PTR_ERR(got) == -EINVAL);

    attr.token_create.bpffs_fd = 0;
    ret = bpf_token_create(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == -EBADF);

    acc += ret + (int)token.refcnt.counter + (int)__bpf_token_work_scheduled;
    return (int)choice + acc;
