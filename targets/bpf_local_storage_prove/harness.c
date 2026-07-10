    /* bpf_local_storage_prove: local-storage guard, cache, and metadata invariants. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    __u64 choice = input ? *input : 0;
    int acc = 0;

    {
        union bpf_attr attr = {};
        int ret;

        attr.map_flags = BPF_F_NO_PREALLOC;
        attr.max_entries = 0;
        attr.key_size = sizeof(int);
        attr.value_size = 8;
        attr.btf_key_type_id = 1;
        attr.btf_value_type_id = 2;
        BPF_KEEP_SCALAR(attr.map_flags);
        BPF_KEEP_SCALAR(attr.max_entries);
        BPF_KEEP_SCALAR(attr.key_size);
        BPF_KEEP_SCALAR(attr.value_size);
        BPF_KEEP_SCALAR(attr.btf_key_type_id);
        BPF_KEEP_SCALAR(attr.btf_value_type_id);
        ret = bpf_local_storage_map_alloc_check(&attr);
        BPF_KEEP_SCALAR(ret);
        BPF_PROVE(ret == 0);

        attr.map_flags = BPF_F_NO_PREALLOC | BPF_F_CLONE;
        BPF_KEEP_SCALAR(attr.map_flags);
        ret = bpf_local_storage_map_alloc_check(&attr);
        BPF_KEEP_SCALAR(ret);
        BPF_PROVE(ret == 0);

        attr.map_flags = BPF_F_NO_PREALLOC | (1U << 31);
        BPF_KEEP_SCALAR(attr.map_flags);
        ret = bpf_local_storage_map_alloc_check(&attr);
        BPF_KEEP_SCALAR(ret);
        BPF_PROVE(ret == -EINVAL);

        attr.map_flags = BPF_F_CLONE;
        BPF_KEEP_SCALAR(attr.map_flags);
        ret = bpf_local_storage_map_alloc_check(&attr);
        BPF_KEEP_SCALAR(ret);
        BPF_PROVE(ret == -EINVAL);
        attr.map_flags = BPF_F_NO_PREALLOC;

        attr.max_entries = 1;
        BPF_KEEP_SCALAR(attr.max_entries);
        ret = bpf_local_storage_map_alloc_check(&attr);
        BPF_KEEP_SCALAR(ret);
        BPF_PROVE(ret == -EINVAL);
        attr.max_entries = 0;

        attr.key_size = sizeof(int) + 1;
        BPF_KEEP_SCALAR(attr.key_size);
        ret = bpf_local_storage_map_alloc_check(&attr);
        BPF_KEEP_SCALAR(ret);
        BPF_PROVE(ret == -EINVAL);
        attr.key_size = sizeof(int);

        attr.value_size = 0;
        BPF_KEEP_SCALAR(attr.value_size);
        ret = bpf_local_storage_map_alloc_check(&attr);
        BPF_KEEP_SCALAR(ret);
        BPF_PROVE(ret == -EINVAL);
        attr.value_size = 8;

        attr.btf_key_type_id = 0;
        BPF_KEEP_SCALAR(attr.btf_key_type_id);
        ret = bpf_local_storage_map_alloc_check(&attr);
        BPF_KEEP_SCALAR(ret);
        BPF_PROVE(ret == -EINVAL);
        attr.btf_key_type_id = 1;

        attr.btf_value_type_id = 0;
        BPF_KEEP_SCALAR(attr.btf_value_type_id);
        ret = bpf_local_storage_map_alloc_check(&attr);
        BPF_KEEP_SCALAR(ret);
        BPF_PROVE(ret == -EINVAL);
        attr.btf_value_type_id = 2;

        attr.value_size = BPF_LOCAL_STORAGE_MAX_VALUE_SIZE + 1;
        BPF_KEEP_SCALAR(attr.value_size);
        ret = bpf_local_storage_map_alloc_check(&attr);
        BPF_KEEP_SCALAR(ret);
        BPF_PROVE(ret == -E2BIG);
        acc += ret;
    }

    {
        struct bpf_local_storage_map_bucket buckets[2] = {};
        struct bpf_local_storage_map smap = {};
        struct bpf_local_storage_map other_smap = {};
        struct bpf_local_storage storage = {};
        struct bpf_local_storage_elem selem0 = {};
        struct bpf_local_storage_data stale_sdata = {};
        struct btf btf = {};
        struct btf_type key_i32 = { .kind = BTF_KIND_INT, .size = sizeof(int) };
        struct btf_type key_i64 = { .kind = BTF_KIND_INT, .size = 8 };
        struct btf_type key_unknown = {
            .kind = BTF_KIND_UNKN,
            .size = sizeof(int),
        };
        struct bpf_local_storage_data *sdata;
        int ret;

        ret = bpf_local_storage_map_check_btf(&smap.map, &btf, &key_i32,
                                              NULL);
        BPF_KEEP_SCALAR(ret);
        BPF_PROVE(ret == 0);
        ret = bpf_local_storage_map_check_btf(&smap.map, &btf, &key_i64,
                                              NULL);
        BPF_KEEP_SCALAR(ret);
        BPF_PROVE(ret == -EINVAL);
        ret = bpf_local_storage_map_check_btf(&smap.map, &btf, &key_unknown,
                                              NULL);
        BPF_KEEP_SCALAR(ret);
        BPF_PROVE(ret == -EINVAL);
        ret = bpf_local_storage_map_check_btf(&smap.map, &btf, NULL, NULL);
        BPF_KEEP_SCALAR(ret);
        BPF_PROVE(ret == -EINVAL);

        BPF_PROVE(check_flags(NULL, 0) == 0);
        BPF_PROVE(check_flags(NULL, BPF_NOEXIST) == 0);
        BPF_PROVE(check_flags(NULL, BPF_EXIST) == -ENOENT);
        BPF_PROVE(check_flags(&selem0.sdata, BPF_EXIST) == 0);
        BPF_PROVE(check_flags(&selem0.sdata, BPF_NOEXIST) == -EEXIST);
        BPF_PROVE(check_flags(&selem0.sdata, BPF_NOEXIST | BPF_F_LOCK) ==
                  -EEXIST);

        smap.buckets = buckets;
        smap.bucket_log = 1;
        smap.elem_size = 32;
        smap.cache_idx = 3;
        other_smap.buckets = buckets;
        other_smap.bucket_log = 1;
        other_smap.cache_idx = 3;
        BPF_PROVE(bpf_local_storage_map_mem_usage(&smap.map) ==
                  sizeof(smap) + sizeof(buckets[0]) * 2);

        INIT_HLIST_HEAD(&storage.list);
        INIT_HLIST_HEAD(&buckets[0].list);
        INIT_HLIST_NODE(&selem0.snode);
        INIT_HLIST_NODE(&selem0.map_node);
        selem0.sdata.smap = &smap;

        BPF_PROVE(!selem_linked_to_storage(&selem0));
        BPF_PROVE(!selem_linked_to_storage_lockless(&selem0));
        bpf_selem_link_storage_nolock(&storage, &selem0);
        BPF_PROVE(selem_linked_to_storage(&selem0));
        BPF_PROVE(selem_linked_to_storage_lockless(&selem0));
        BPF_PROVE(storage.mem_charge == 32);
        BPF_PROVE(selem0.local_storage == &storage);

        stale_sdata.smap = &other_smap;
        storage.cache[3] = &stale_sdata;
        sdata = bpf_local_storage_lookup(&storage, &smap, false);
        BPF_ASSERT(sdata == &selem0.sdata);
        BPF_ASSERT(storage.cache[3] == &stale_sdata);
        storage.cache[3] = NULL;

        sdata = bpf_local_storage_lookup(&storage, &smap, false);
        BPF_ASSERT(sdata == &selem0.sdata);
        BPF_ASSERT(storage.cache[3] == NULL);
        sdata = bpf_local_storage_lookup(&storage, &other_smap, false);
        BPF_ASSERT(sdata == NULL);
        sdata = bpf_local_storage_lookup(&storage, &smap, true);
        BPF_ASSERT(sdata == &selem0.sdata);
        BPF_ASSERT(storage.cache[3] == &selem0.sdata);
        sdata = bpf_local_storage_lookup(&storage, &smap, true);
        BPF_ASSERT(sdata == &selem0.sdata);

        BPF_PROVE(!selem_linked_to_map(&selem0));
        bpf_selem_link_map_nolock(&buckets[0], &selem0);
        BPF_PROVE(selem_linked_to_map(&selem0));
        BPF_PROVE(buckets[0].list.first == &selem0.map_node);
        bpf_selem_unlink_map_nolock(&selem0);
        BPF_PROVE(!selem_linked_to_map(&selem0));
        BPF_PROVE(buckets[0].list.first == NULL);

        {
            struct hlist_head free_list = {};
            struct hlist_head free_list2 = {};
            struct hlist_node extra_node = {};
            struct bpf_local_storage *owner_slot;
            bool free_storage;

            INIT_HLIST_HEAD(&storage.list);
            INIT_HLIST_HEAD(&free_list);
            INIT_HLIST_NODE(&selem0.snode);
            INIT_HLIST_NODE(&selem0.free_node);
            INIT_HLIST_NODE(&extra_node);
            owner_slot = &storage;
            storage.mem_charge = 0;
            storage.owner = &owner_slot;
            storage.cache[3] = NULL;
            bpf_selem_link_storage_nolock(&storage, &selem0);
            hlist_add_head_rcu(&extra_node, &storage.list);
            storage.cache[3] = &selem0.sdata;
            free_storage = bpf_selem_unlink_storage_nolock(&storage,
                                                           &selem0,
                                                           &free_list);
            BPF_PROVE(!free_storage);
            BPF_PROVE(!selem_linked_to_storage(&selem0));
            BPF_PROVE(storage.cache[3] == NULL);
            BPF_PROVE(storage.mem_charge == 0);
            BPF_PROVE(storage.list.first == &extra_node);
            BPF_PROVE(extra_node.next == NULL);
            BPF_PROVE(free_list.first == &selem0.free_node);

            INIT_HLIST_HEAD(&storage.list);
            INIT_HLIST_HEAD(&free_list2);
            INIT_HLIST_NODE(&selem0.snode);
            INIT_HLIST_NODE(&selem0.free_node);
            owner_slot = &storage;
            storage.mem_charge = sizeof(storage);
            storage.owner = &owner_slot;
            storage.cache[3] = &selem0.sdata;
            bpf_selem_link_storage_nolock(&storage, &selem0);
            free_storage = bpf_selem_unlink_storage_nolock(&storage,
                                                           &selem0,
                                                           &free_list2);
            BPF_PROVE(free_storage);
            BPF_PROVE(!selem_linked_to_storage(&selem0));
            BPF_PROVE(storage.cache[3] == NULL);
            BPF_PROVE(storage.mem_charge == 0);
            BPF_PROVE(storage.owner == NULL);
            BPF_PROVE(owner_slot == NULL);
            BPF_PROVE(storage.list.first == NULL);
            BPF_PROVE(free_list2.first == &selem0.free_node);
        }
        acc += ret;
    }

    {
        struct bpf_local_storage_cache cache = {};
        u16 idx;

        cache.idx_usage_counts[0] = 2;
        cache.idx_usage_counts[1] = 1;
        idx = bpf_local_storage_cache_idx_get(&cache);
        BPF_PROVE(idx == 2);
        BPF_PROVE(cache.idx_usage_counts[2] == 1);
        bpf_local_storage_cache_idx_free(&cache, idx);
        BPF_PROVE(cache.idx_usage_counts[2] == 0);
        acc += idx;
    }

    acc += (int)choice;
    return acc;
