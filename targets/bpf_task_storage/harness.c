    /* bpf_task_storage: pidfd wrappers, helper paths, map ops, and free. */
    struct bpf_map *map = &__bpf_storage_smap.map;
    int key = 1;
    int bad_key = 9;
    u64 value = 0xabcdef;
    void *ptr;
    u32 errors = 0;

    __bpf_storage_reset();
    errors |= bpf_pid_task_storage_lookup_elem(map, &key) != NULL;
    errors |= bpf_pid_task_storage_update_elem(map, &key, &value,
                                               BPF_NOEXIST) != 0;
    ptr = bpf_pid_task_storage_lookup_elem(map, &key);
    errors |= ptr != __bpf_storage_elem.sdata.data;
    errors |= bpf_task_storage_get(map, &__bpf_storage_task, NULL, 0) !=
              (unsigned long)__bpf_storage_elem.sdata.data;
    errors |= bpf_task_storage_get(map, NULL, NULL,
                                   BPF_LOCAL_STORAGE_GET_F_CREATE) != 0;
    errors |= bpf_task_storage_delete(map, &__bpf_storage_task) != 0;
    errors |= bpf_pid_task_storage_lookup_elem(map, &key) != NULL;
    errors |= bpf_pid_task_storage_delete_elem(map, &key) != -ENOENT;
    errors |= bpf_pid_task_storage_lookup_elem(map, &bad_key) != ERR_PTR(-EBADF);
    errors |= bpf_pid_task_storage_update_elem(map, &bad_key, &value, 0) !=
              -EBADF;
    errors |= bpf_pid_task_storage_delete_elem(map, &bad_key) != -EBADF;
    errors |= task_storage_map_ops.map_get_next_key(map, &key, &bad_key) !=
              -ENOTSUPP;
    errors |= task_storage_map_alloc(NULL) != map;
    task_storage_map_free(map);
    bpf_task_storage_free(&__bpf_storage_task);

    return (int)(errors + __bpf_storage_updates + __bpf_storage_deletes +
                 __bpf_storage_destroys + __bpf_storage_pid_puts);