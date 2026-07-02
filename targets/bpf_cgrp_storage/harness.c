    /* bpf_cgrp_storage: cgroup fd wrappers, helper paths, map ops, and free. */
    struct bpf_map *map = &__bpf_storage_smap.map;
    int key = 1;
    int bad_key = 9;
    u64 value = 0x12345678;
    void *ptr;
    u32 errors = 0;

    __bpf_storage_reset();
    errors |= bpf_cgrp_storage_lookup_elem(map, &key) != NULL;
    errors |= bpf_cgrp_storage_update_elem(map, &key, &value, BPF_NOEXIST) != 0;
    ptr = bpf_cgrp_storage_lookup_elem(map, &key);
    errors |= ptr != __bpf_storage_elem.sdata.data;
    errors |= bpf_cgrp_storage_get(map, &__bpf_storage_cgroup, NULL, 0) !=
              (unsigned long)__bpf_storage_elem.sdata.data;
    errors |= bpf_cgrp_storage_get(map, NULL, NULL,
                                   BPF_LOCAL_STORAGE_GET_F_CREATE) != 0;
    errors |= bpf_cgrp_storage_delete(map, &__bpf_storage_cgroup) != 0;
    errors |= bpf_cgrp_storage_lookup_elem(map, &key) != NULL;
    errors |= bpf_cgrp_storage_delete_elem(map, &key) != -ENOENT;
    errors |= bpf_cgrp_storage_lookup_elem(map, &bad_key) != ERR_PTR(-EBADF);
    errors |= bpf_cgrp_storage_update_elem(map, &bad_key, &value, 0) != -EBADF;
    errors |= bpf_cgrp_storage_delete_elem(map, &bad_key) != -EBADF;
    errors |= cgrp_storage_map_ops.map_get_next_key(map, &key, &bad_key) !=
              -ENOTSUPP;
    errors |= cgroup_storage_map_alloc(NULL) != map;
    cgroup_storage_map_free(map);
    bpf_cgrp_storage_free(&__bpf_storage_cgroup);

    return (int)(errors + __bpf_storage_updates + __bpf_storage_deletes +
                 __bpf_storage_destroys + __bpf_storage_cgroup_puts);