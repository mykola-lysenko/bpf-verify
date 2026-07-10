    /* token_create_prove: VFS-backed bpf_token_create() guard ladder and
     * successful pseudo-file token installation. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    __u64 choice = input ? *input : 0;
    union bpf_attr attr = {};
    struct bpf_token *created;
    struct bpf_token *got;
    int ret;
    int acc = 0;

    attr.token_create.bpffs_fd = 1;

    __bpf_token_reset_create_controls();
    __bpf_token_use_child_dentry = 1;
    ret = bpf_token_create(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    __bpf_token_reset_create_controls();
    __bpf_token_bad_super_ops = 1;
    ret = bpf_token_create(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    __bpf_token_reset_create_controls();
    __bpf_token_path_permission_ret = -EACCES;
    ret = bpf_token_create(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EACCES);

    __bpf_token_reset_create_controls();
    __bpf_token_current_mismatch = 1;
    ret = bpf_token_create(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EPERM);

    __bpf_token_reset_create_controls();
    __bpf_token_clear_caps = 1;
    ret = bpf_token_create(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EPERM);

    __bpf_token_reset_create_controls();
    __bpf_token_use_init_userns = 1;
    ret = bpf_token_create(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == -EOPNOTSUPP);

    __bpf_token_reset_create_controls();
    __bpf_token_empty_delegation = 1;
    ret = bpf_token_create(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -ENOENT);

    __bpf_token_reset_create_controls();
    __bpf_token_inode_err = -ENOMEM;
    ret = bpf_token_create(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -ENOMEM);

    __bpf_token_reset_create_controls();
    __bpf_token_alloc_file_err = -EMFILE;
    ret = bpf_token_create(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == -EMFILE);

    __bpf_token_reset_create_controls();
    __bpf_token_alloc_fail = 1;
    ret = bpf_token_create(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == -ENOMEM);

    __bpf_token_reset_create_controls();
    __bpf_token_security_create_ret = -EACCES;
    ret = bpf_token_create(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == -EACCES);
    BPF_ASSERT(__bpf_token_userns_gets == 0);

    __bpf_token_reset_create_controls();
    ret = bpf_token_create(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_ASSERT(ret == 7);
    BPF_ASSERT(__bpf_token_kzallocs == 1);
    BPF_ASSERT(__bpf_token_userns_gets == 1);
    BPF_ASSERT(__bpf_token_inode.i_op == &bpf_token_iops);
    BPF_ASSERT(__bpf_token_inode.i_fop == &bpf_token_fops);
    BPF_ASSERT(__bpf_token_file.f_op == &bpf_token_fops);

    created = __bpf_token_file.private_data;
    BPF_ASSERT(created == &__bpf_token_alloc);
    BPF_ASSERT(created->refcnt.counter == 1);
    BPF_ASSERT(created->userns == &__bpf_token_owner_ns);
    BPF_ASSERT(created->allowed_cmds == BIT_ULL(BPF_MAP_CREATE));
    BPF_ASSERT(created->allowed_maps == BIT_ULL(BPF_MAP_TYPE_ARRAY));
    BPF_ASSERT(created->allowed_progs ==
              BIT_ULL(BPF_PROG_TYPE_SOCKET_FILTER));
    BPF_ASSERT(created->allowed_attachs == BIT_ULL(BPF_CGROUP_INET_INGRESS));

    got = bpf_token_get_from_fd(1);
    BPF_ASSERT(got == created);
    BPF_ASSERT(created->refcnt.counter == 2);

    acc += ret + (int)created->refcnt.counter + (int)__bpf_token_userns_gets;
    return (int)choice + acc;
