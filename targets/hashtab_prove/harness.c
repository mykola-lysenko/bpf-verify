    /* hashtab_prove: verifier-enforced hash-map guard/layout invariants. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    __u64 choice = input ? *input : 0;
    struct {
        struct bpf_htab htab;
        char elems[160];
    } storage = {};
    struct {
        struct htab_elem elem;
        char payload[64];
    } elem_storage = {};
    struct bpf_htab *htab = &storage.htab;
    struct bpf_map *map = &htab->map;
    struct htab_elem *elem = &elem_storage.elem;
    union bpf_attr attr = {};
    char target = 7;
    void *value;
    u64 expected_usage;
    u64 flags;
    int ret;
    int acc = 0;

    attr.map_type = BPF_MAP_TYPE_HASH;
    attr.key_size = 4;
    attr.value_size = 8;
    attr.max_entries = 4;
    attr.map_flags = 0;
    attr.numa_node = 0;
    BPF_KEEP_SCALAR(attr.map_type);
    BPF_KEEP_SCALAR(attr.key_size);
    BPF_KEEP_SCALAR(attr.value_size);
    BPF_KEEP_SCALAR(attr.max_entries);
    BPF_KEEP_SCALAR(attr.map_flags);
    ret = htab_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);

    attr.map_type = BPF_MAP_TYPE_PERCPU_HASH;
    ret = htab_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);

    attr.map_type = BPF_MAP_TYPE_LRU_HASH;
    attr.map_flags = BPF_F_NO_COMMON_LRU;
    BPF_KEEP_SCALAR(attr.map_type);
    BPF_KEEP_SCALAR(attr.map_flags);
    ret = htab_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);

    attr.map_type = BPF_MAP_TYPE_HASH;
    attr.map_flags = BPF_F_ZERO_SEED;
    BPF_KEEP_SCALAR(attr.map_flags);
    ret = htab_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EPERM);

    attr.map_flags = 1U << 31;
    BPF_KEEP_SCALAR(attr.map_flags);
    ret = htab_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    attr.map_flags = BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG;
    BPF_KEEP_SCALAR(attr.map_flags);
    ret = htab_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    attr.map_flags = BPF_F_NO_COMMON_LRU;
    BPF_KEEP_SCALAR(attr.map_flags);
    ret = htab_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    attr.map_type = BPF_MAP_TYPE_LRU_HASH;
    attr.map_flags = BPF_F_NO_PREALLOC;
    BPF_KEEP_SCALAR(attr.map_type);
    BPF_KEEP_SCALAR(attr.map_flags);
    ret = htab_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -ENOTSUPP);

    attr.map_type = BPF_MAP_TYPE_PERCPU_HASH;
    attr.map_flags = BPF_F_NUMA_NODE;
    attr.numa_node = 0;
    BPF_KEEP_SCALAR(attr.map_type);
    BPF_KEEP_SCALAR(attr.map_flags);
    BPF_KEEP_SCALAR(attr.numa_node);
    ret = htab_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    attr.map_type = BPF_MAP_TYPE_HASH;
    attr.map_flags = 0;
    attr.max_entries = 0;
    BPF_KEEP_SCALAR(attr.max_entries);
    ret = htab_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    attr.max_entries = 4;

    attr.key_size = 0;
    BPF_KEEP_SCALAR(attr.key_size);
    ret = htab_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    attr.key_size = 4;

    attr.value_size = 0;
    BPF_KEEP_SCALAR(attr.value_size);
    ret = htab_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    attr.value_size = 8;

    attr.key_size = KMALLOC_MAX_SIZE;
    BPF_KEEP_SCALAR(attr.key_size);
    ret = htab_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -E2BIG);
    attr.key_size = 4;

    attr.map_type = BPF_MAP_TYPE_PERCPU_HASH;
    attr.value_size = PCPU_MIN_UNIT_SIZE + 1;
    BPF_KEEP_SCALAR(attr.map_type);
    BPF_KEEP_SCALAR(attr.value_size);
    ret = htab_map_alloc_check(&attr);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -E2BIG);

    ret = htab_map_check_update_flags(false, BPF_EXIST);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = htab_map_check_update_flags(false, BPF_EXIST + 1);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    ret = htab_map_check_update_flags(true, BPF_F_ALL_CPUS);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    flags = (1ULL << 32) | BPF_F_ALL_CPUS;
    BPF_KEEP_SCALAR(flags);
    ret = htab_map_check_update_flags(true, flags);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = htab_map_check_update_flags(true, BPF_F_LOCK);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    ret = htab_map_check_update_flags(true, BPF_F_ALL_CPUS + 1);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    map->map_type = BPF_MAP_TYPE_HASH;
    map->map_flags = 0;
    BPF_ASSERT(htab_is_prealloc(htab));
    BPF_ASSERT(!htab_is_lru(htab));
    BPF_ASSERT(!htab_is_percpu(htab));
    BPF_ASSERT(!is_fd_htab(htab));
    BPF_ASSERT(htab_has_extra_elems(htab));

    map->map_flags = BPF_F_NO_PREALLOC;
    BPF_ASSERT(!htab_is_prealloc(htab));
    map->map_flags = 0;
    map->map_type = BPF_MAP_TYPE_LRU_HASH;
    BPF_ASSERT(htab_is_lru(htab));
    BPF_ASSERT(!htab_has_extra_elems(htab));
    map->map_type = BPF_MAP_TYPE_LRU_PERCPU_HASH;
    BPF_ASSERT(htab_is_lru(htab));
    BPF_ASSERT(htab_is_percpu(htab));
    BPF_ASSERT(!htab_has_extra_elems(htab));
    map->map_type = BPF_MAP_TYPE_HASH_OF_MAPS;
    BPF_ASSERT(is_fd_htab(htab));
    BPF_ASSERT(!htab_has_extra_elems(htab));

    value = htab_elem_value(elem, 5);
    BPF_ASSERT(value == elem->key + 8);
    htab_elem_set_ptr(elem, 5, &target);
    BPF_ASSERT(htab_elem_get_ptr(elem, 5) == &target);
    map->key_size = 5;
    BPF_ASSERT(fd_htab_map_get_ptr(map, elem) == &target);

    htab->elems = storage.elems;
    htab->elem_size = 32;
    BPF_ASSERT(get_htab_elem(htab, 2) ==
               (struct htab_elem *)(storage.elems + 64));

    map->max_entries = 3;
    map->elem_count = 2;
    htab->use_percpu_counter = false;
    atomic_set(&htab->count, 2);
    BPF_ASSERT(!is_map_full(htab));
    inc_elem_count(htab);
    BPF_ASSERT(is_map_full(htab));
    BPF_ASSERT(map->elem_count == 3);
    BPF_ASSERT(atomic_read(&htab->count) == 3);
    dec_elem_count(htab);
    BPF_ASSERT(map->elem_count == 2);
    BPF_ASSERT(atomic_read(&htab->count) == 2);

    htab->use_percpu_counter = true;
    map->elem_count = 3;
    percpu_counter_set(&htab->pcount, 3);
    BPF_ASSERT(is_map_full(htab));
    dec_elem_count(htab);
    BPF_ASSERT(map->elem_count == 2);
    BPF_ASSERT(percpu_counter_sum(&htab->pcount) == 2);
    inc_elem_count(htab);
    BPF_ASSERT(map->elem_count == 3);
    BPF_ASSERT(percpu_counter_sum(&htab->pcount) == 3);

    htab->n_buckets = 4;
    htab->elem_size = 32;
    htab->use_percpu_counter = false;
    map->map_type = BPF_MAP_TYPE_HASH;
    map->map_flags = 0;
    map->max_entries = 2;
    map->value_size = 5;
    expected_usage = sizeof(struct bpf_htab) + sizeof(struct bucket) * 4;
    expected_usage += 32 * (2 + HTAB_TEST_NR_CPUS);
    expected_usage += sizeof(struct htab_elem *) * HTAB_TEST_NR_CPUS;
    BPF_ASSERT(htab_map_mem_usage(map) == expected_usage);

    map->map_type = BPF_MAP_TYPE_PERCPU_HASH;
    expected_usage = sizeof(struct bpf_htab) + sizeof(struct bucket) * 4;
    expected_usage += 32 * 2;
    expected_usage += 8 * HTAB_TEST_NR_CPUS * 2;
    BPF_ASSERT(htab_map_mem_usage(map) == expected_usage);

    map->map_type = BPF_MAP_TYPE_LRU_HASH;
    expected_usage = sizeof(struct bpf_htab) + sizeof(struct bucket) * 4;
    expected_usage += 32 * 2;
    BPF_ASSERT(htab_map_mem_usage(map) == expected_usage);

    map->map_type = BPF_MAP_TYPE_HASH;
    map->map_flags = BPF_F_NO_PREALLOC;
    atomic_set(&htab->count, 3);
    expected_usage = sizeof(struct bpf_htab) + sizeof(struct bucket) * 4;
    expected_usage += (32 + sizeof(struct llist_node)) * 3;
    BPF_ASSERT(htab_map_mem_usage(map) == expected_usage);

    map->map_type = BPF_MAP_TYPE_PERCPU_HASH;
    expected_usage = sizeof(struct bpf_htab) + sizeof(struct bucket) * 4;
    expected_usage += (32 + sizeof(struct llist_node)) * 3;
    expected_usage += (sizeof(struct llist_node) + sizeof(void *)) * 3;
    expected_usage += 8 * HTAB_TEST_NR_CPUS * 3;
    BPF_ASSERT(htab_map_mem_usage(map) == expected_usage);

    acc += ret + (int)map->elem_count + (int)choice;
    return acc;
