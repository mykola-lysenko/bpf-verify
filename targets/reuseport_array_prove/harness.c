    /* reuseport_array_prove: verifier-enforced reuseport map invariants.
     *
     * Lookup/delete keys are fixed because a symbolic index into stack-backed
     * ptrs[] becomes a verifier-rejected variable-offset stack read. The
     * get_next_key scalar path remains symbolic.
     */
    __u32 input_key = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &input_key);
    if (!vp) return 0;

    struct __bpf_reuseport_array_4 storage = {};
    struct reuseport_array *array = (struct reuseport_array *)&storage;
    struct bpf_map *map = &storage.map;
    struct sock_reuseport reuse = {};
    struct sock sk0 = {};
    struct sock sk1 = {};
    union bpf_attr attr = {};
    u32 key;
    u32 next = 0;
    u64 cookie = 0;
    u64 fd64 = 0;
    int fd = -1;
    int rc;

    map->key_size = sizeof(u32);
    map->value_size = sizeof(u64);
    map->max_entries = 4;
    __bpf_reuseport_init_sock(&sk0, IPPROTO_UDP, AF_INET, SOCK_DGRAM,
                              &reuse, 0x12345678ULL);
    __bpf_reuseport_init_sock(&sk1, IPPROTO_TCP, AF_INET6, SOCK_STREAM,
                              &reuse, 0xabcdef01ULL);
    storage.ptrs[0] = &sk0;
    storage.ptrs[1] = &sk0;
    storage.ptrs[2] = &sk1;
    storage.ptrs[3] = &sk1;

    attr.key_size = sizeof(u32);
    attr.value_size = sizeof(u32);
    attr.max_entries = 4;
    BPF_PROVE(reuseport_array_alloc_check(&attr) == 0);
    attr.value_size = sizeof(u64);
    BPF_PROVE(reuseport_array_alloc_check(&attr) == 0);
    attr.value_size = sizeof(u16);
    BPF_PROVE(reuseport_array_alloc_check(&attr) == -EINVAL);
    attr.value_size = sizeof(u64);
    attr.max_entries = 0;
    BPF_PROVE(reuseport_array_alloc_check(&attr) == -EINVAL);
    attr.max_entries = 5;
    BPF_PROVE(reuseport_array_alloc_check(&attr) == -EINVAL);
    BPF_PROVE(reuseport_array_mem_usage(map) == sizeof(storage));

    key = 0;
    BPF_PROVE(reuseport_array_lookup_elem(map, &key) == &sk0);
    key = 2;
    BPF_PROVE(reuseport_array_lookup_elem(map, &key) == &sk1);
    key = 4;
    BPF_PROVE(reuseport_array_lookup_elem(map, &key) == NULL);

    key = 2;
    BPF_PROVE(bpf_fd_reuseport_array_lookup_elem(map, &key, &cookie) == 0);
    BPF_PROVE(cookie == 0xabcdef01ULL);
    key = 4;
    BPF_PROVE(bpf_fd_reuseport_array_lookup_elem(map, &key, &cookie) ==
              -ENOENT);
    map->value_size = sizeof(u32);
    key = 0;
    BPF_PROVE(bpf_fd_reuseport_array_lookup_elem(map, &key, &cookie) ==
              -ENOSPC);
    map->value_size = sizeof(u64);

    BPF_PROVE(reuseport_array_update_check(array, &sk0, NULL, &reuse,
                                           BPF_NOEXIST) == 0);
    BPF_PROVE(reuseport_array_update_check(array, &sk0, &sk1, &reuse,
                                           BPF_NOEXIST) == -EEXIST);
    BPF_PROVE(reuseport_array_update_check(array, &sk0, NULL, &reuse,
                                           BPF_EXIST) == -ENOENT);
    sk0.sk_protocol = 1;
    BPF_PROVE(reuseport_array_update_check(array, &sk0, NULL, &reuse,
                                           BPF_NOEXIST) == -ENOTSUPP);
    sk0.sk_protocol = IPPROTO_UDP;
    sk0.sk_family = 1;
    BPF_PROVE(reuseport_array_update_check(array, &sk0, NULL, &reuse,
                                           BPF_NOEXIST) == -ENOTSUPP);
    sk0.sk_family = AF_INET;
    sk0.sk_type = 3;
    BPF_PROVE(reuseport_array_update_check(array, &sk0, NULL, &reuse,
                                           BPF_NOEXIST) == -ENOTSUPP);
    sk0.sk_type = SOCK_DGRAM;
    sk0.sk_flags = 0;
    BPF_PROVE(reuseport_array_update_check(array, &sk0, NULL, &reuse,
                                           BPF_NOEXIST) == -EINVAL);
    sk0.sk_flags = 1UL << SOCK_RCU_FREE;
    sk0.hashed = false;
    BPF_PROVE(reuseport_array_update_check(array, &sk0, NULL, &reuse,
                                           BPF_NOEXIST) == -EINVAL);
    sk0.hashed = true;
    BPF_PROVE(reuseport_array_update_check(array, &sk0, NULL, NULL,
                                           BPF_NOEXIST) == -EINVAL);
    sk0.sk_user_data = &storage.ptrs[0];
    BPF_PROVE(reuseport_array_update_check(array, &sk0, NULL, &reuse,
                                           BPF_NOEXIST) == -EBUSY);
    sk0.sk_user_data = NULL;

    key = 4;
    BPF_PROVE(bpf_fd_reuseport_array_update_elem(map, &key, &fd64,
                                                 BPF_ANY) == -E2BIG);
    key = 0;
    BPF_PROVE(bpf_fd_reuseport_array_update_elem(map, &key, &fd64,
                                                 BPF_EXIST + 1) == -EINVAL);
    fd64 = (u64)S32_MAX + 1;
    BPF_PROVE(bpf_fd_reuseport_array_update_elem(map, &key, &fd64,
                                                 BPF_ANY) == -EINVAL);
    map->value_size = sizeof(u32);
    BPF_PROVE(bpf_fd_reuseport_array_update_elem(map, &key, &fd,
                                                 BPF_ANY) == -EBADF);
    map->value_size = sizeof(u64);

    key = 1;
    sk0.sk_user_data = &storage.ptrs[1];
    BPF_PROVE(reuseport_array_delete_elem(map, &key) == 0);
    BPF_PROVE(storage.ptrs[1] == NULL);
    BPF_PROVE(sk0.sk_user_data == NULL);
    BPF_PROVE(reuseport_array_delete_elem(map, &key) == -ENOENT);
    key = 4;
    BPF_PROVE(reuseport_array_delete_elem(map, &key) == -E2BIG);

    BPF_PROVE(reuseport_array_get_next_key(map, NULL, &next) == 0);
    BPF_PROVE(next == 0);
    key = (u32)((*vp >> 32) & 7);
    rc = reuseport_array_get_next_key(map, &key, &next);
    if (key < 3) {
        BPF_PROVE(rc == 0);
        BPF_PROVE(next == key + 1);
    } else if (key == 3) {
        BPF_PROVE(rc == -ENOENT);
    } else {
        BPF_PROVE(rc == 0);
        BPF_PROVE(next == 0);
    }

    return (int)(key + next + cookie + fd + (*vp & 1));
