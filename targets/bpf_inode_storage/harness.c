    /* bpf_inode_storage: fd wrappers, helper paths, map ops, and free. */
    struct bpf_map *map = &__bpf_storage_smap.map;
    int key = 1;
    int bad_key = 9;
    u64 value = 0xfeedface;
    void *ptr;
    u32 errors = 0;

    __bpf_storage_reset();
    errors |= bpf_fd_inode_storage_lookup_elem(map, &key) != NULL;
    errors |= bpf_fd_inode_storage_update_elem(map, &key, &value,
                                               BPF_NOEXIST) != 0;
    ptr = bpf_fd_inode_storage_lookup_elem(map, &key);
    errors |= ptr != __bpf_storage_elem.sdata.data;
    errors |= bpf_inode_storage_get(map, &__bpf_storage_inode, NULL, 0) !=
              (unsigned long)__bpf_storage_elem.sdata.data;
    errors |= bpf_inode_storage_get(map, NULL, NULL,
                                    BPF_LOCAL_STORAGE_GET_F_CREATE) != 0;
    errors |= bpf_inode_storage_delete(map, &__bpf_storage_inode) != 0;
    errors |= bpf_fd_inode_storage_lookup_elem(map, &key) != NULL;
    errors |= bpf_fd_inode_storage_delete_elem(map, &key) != -ENOENT;
    errors |= bpf_fd_inode_storage_lookup_elem(map, &bad_key) != ERR_PTR(-EBADF);
    errors |= bpf_fd_inode_storage_update_elem(map, &bad_key, &value, 0) !=
              -EBADF;
    errors |= bpf_fd_inode_storage_delete_elem(map, &bad_key) != -EBADF;
    errors |= inode_storage_map_ops.map_get_next_key(map, &key, &bad_key) !=
              -ENOTSUPP;
    errors |= inode_storage_map_alloc(NULL) != map;
    inode_storage_map_free(map);
    bpf_inode_storage_free(&__bpf_storage_inode);

    return (int)(errors + __bpf_storage_updates + __bpf_storage_deletes +
                 __bpf_storage_destroys + __bpf_storage_fd_gets);