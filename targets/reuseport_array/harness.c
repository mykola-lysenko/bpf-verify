    /* reuseport_array: reuseport socket array map behavior.
     *
     * Covered here:
     *   1. allocation validation/allocation and memory accounting.
     *   2. lookup, fd-lookup cookie return, delete, free, and detach cleanup.
     *   3. update precondition validation and fd-update early error paths.
     */
    struct __bpf_reuseport_array_4 storage = {};
    struct reuseport_array *array = (struct reuseport_array *)&storage;
    struct bpf_map *map = &storage.map;
    struct sock_reuseport reuse = {};
    struct sock sk0 = {};
    struct sock sk1 = {};
    union bpf_attr attr = {};
    struct sock *found;
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0;
    u64 cookie = 0;
    u64 fd64 = 0;
    int fd = -1;
    int rc = 0;
    u32 key = 0;
    u32 next = 0;
    u32 errors = 0;

    map->key_size = sizeof(u32);
    map->value_size = sizeof(u64);
    map->max_entries = 4;
    __bpf_reuseport_init_sock(&sk0, IPPROTO_UDP, AF_INET, SOCK_DGRAM,
                              &reuse, 0x12345678ULL);
    __bpf_reuseport_init_sock(&sk1, IPPROTO_TCP, AF_INET6, SOCK_STREAM,
                              &reuse, 0xabcdef01ULL);

    attr.key_size = sizeof(u32);
    attr.value_size = sizeof(u16);
    attr.max_entries = 4;
    errors |= reuseport_array_alloc_check(&attr) != -EINVAL;
    attr.value_size = sizeof(u64);
    errors |= reuseport_array_alloc_check(&attr) != 0;
    errors |= reuseport_array_mem_usage(map) !=
              sizeof(struct bpf_map) + 4 * sizeof(struct sock *);

    __bpf_reuseport_allocated = 0;
    __bpf_reuseport_frees = 0;
    map = reuseport_array_alloc(&attr);
    errors |= IS_ERR(map);
    if (!IS_ERR(map)) {
        errors |= map != &__bpf_reuseport_alloc_array.map;
        errors |= map->key_size != sizeof(u32);
        errors |= map->value_size != sizeof(u64);
        errors |= map->max_entries != 4;
        map->max_entries = 0;
        reuseport_array_free(map);
        errors |= __bpf_reuseport_allocated != 0;
        errors |= __bpf_reuseport_frees != 1;
    }

    map = &storage.map;
    storage.ptrs[0] = &sk0;
    storage.ptrs[1] = &sk0;
    storage.ptrs[2] = &sk1;
    storage.ptrs[3] = &sk1;
    key = seed & 3;
    found = reuseport_array_lookup_elem(map, &key);
    errors |= !found;
    key = 1;
    errors |= bpf_fd_reuseport_array_lookup_elem(map, &key, &cookie) != 0;
    errors |= cookie == 0;
    key = 4;
    errors |= reuseport_array_lookup_elem(map, &key) != NULL;
    map->value_size = sizeof(u32);
    key = 1;
    errors |= bpf_fd_reuseport_array_lookup_elem(map, &key, &cookie) != -ENOSPC;
    map->value_size = sizeof(u64);

    errors |= reuseport_array_update_check(array, &sk0, NULL, &reuse,
                                           BPF_NOEXIST) != 0;
    errors |= reuseport_array_update_check(array, &sk0, &sk1, &reuse,
                                           BPF_NOEXIST) != -EEXIST;
    errors |= reuseport_array_update_check(array, &sk0, NULL, &reuse,
                                           BPF_EXIST) != -ENOENT;
    sk0.sk_protocol = 1;
    errors |= reuseport_array_update_check(array, &sk0, NULL, &reuse,
                                           BPF_NOEXIST) != -ENOTSUPP;
    sk0.sk_protocol = IPPROTO_UDP;
    sk0.sk_family = 1;
    errors |= reuseport_array_update_check(array, &sk0, NULL, &reuse,
                                           BPF_NOEXIST) != -ENOTSUPP;
    sk0.sk_family = AF_INET;
    sk0.sk_type = 1;
    errors |= reuseport_array_update_check(array, &sk0, NULL, &reuse,
                                           BPF_NOEXIST) != -ENOTSUPP;
    sk0.sk_type = SOCK_DGRAM;
    sk0.sk_flags = 0;
    errors |= reuseport_array_update_check(array, &sk0, NULL, &reuse,
                                           BPF_NOEXIST) != -EINVAL;
    sk0.sk_flags = 1UL << SOCK_RCU_FREE;
    sk0.hashed = false;
    errors |= reuseport_array_update_check(array, &sk0, NULL, &reuse,
                                           BPF_NOEXIST) != -EINVAL;
    sk0.hashed = true;
    errors |= reuseport_array_update_check(array, &sk0, NULL, NULL,
                                           BPF_NOEXIST) != -EINVAL;
    sk0.sk_user_data = &storage.ptrs[1];
    errors |= reuseport_array_update_check(array, &sk0, NULL, &reuse,
                                           BPF_NOEXIST) != -EBUSY;
    sk0.sk_user_data = NULL;

    key = seed & 7;
    fd64 = seed;
    rc = bpf_fd_reuseport_array_update_elem(map, &key, &fd64, seed & 3);
    errors ^= rc & 1;
    errors |= bpf_fd_reuseport_array_update_elem(map, &key, &fd64,
                                                 BPF_EXIST + 1) != -EINVAL;
    key = 4;
    errors |= bpf_fd_reuseport_array_update_elem(map, &key, &fd64,
                                                 BPF_ANY) != -E2BIG;
    key = 1;
    fd64 = (u64)S32_MAX + 1;
    errors |= bpf_fd_reuseport_array_update_elem(map, &key, &fd64,
                                                 BPF_ANY) != -EINVAL;
    map->value_size = sizeof(u32);
    errors |= bpf_fd_reuseport_array_update_elem(map, &key, &fd,
                                                 BPF_ANY) != -EBADF;
    map->value_size = sizeof(u64);

    key = 1;
    storage.ptrs[0] = &sk0;
    storage.ptrs[1] = &sk0;
    storage.ptrs[2] = &sk1;
    storage.ptrs[3] = &sk1;
    errors |= reuseport_array_delete_elem(map, &key) != 0;
    errors |= reuseport_array_lookup_elem(map, &key) != NULL;
    errors |= reuseport_array_delete_elem(map, &key) != -ENOENT;
    key = 4;
    errors |= reuseport_array_delete_elem(map, &key) != -E2BIG;

    errors |= reuseport_array_get_next_key(map, NULL, &next) != 0;
    errors |= next != 0;
    key = seed & 7;
    rc = reuseport_array_get_next_key(map, &key, &next);
    if (key < 3)
        errors |= rc != 0 || next != key + 1;
    else if (key == 3)
        errors |= rc != -ENOENT;
    else
        errors |= rc != 0 || next != 0;

    storage.ptrs[0] = &sk1;
    sk1.sk_user_data = &storage.ptrs[0];
    bpf_sk_reuseport_detach(&sk1);
    errors |= storage.ptrs[0] != NULL;
    errors |= sk1.sk_user_data != NULL;

    storage.ptrs[0] = &sk0;
    storage.ptrs[1] = &sk1;
    storage.ptrs[2] = NULL;
    storage.ptrs[3] = NULL;
    sk0.sk_user_data = &storage.ptrs[0];
    sk1.sk_user_data = &storage.ptrs[1];
    reuseport_array_free(map);
    errors |= storage.ptrs[0] != NULL;
    errors |= storage.ptrs[1] != NULL;
    errors |= sk0.sk_user_data != NULL;
    errors |= sk1.sk_user_data != NULL;

    return (int)(errors + __bpf_reuseport_frees + next + (seed & 1));
