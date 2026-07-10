    /* bpf_inode_storage_prove: verifier-enforced inode storage invariants.
     *
     * The assert harness covers successful fd update/lookup/delete state
     * changes. This proof avoids volatile storage-presence reads and BSS
     * pointer IS_ERR() ambiguity, then proves guard paths and map/proto
     * metadata.
     */
    __u32 input_key = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &input_key);
    if (!vp) return 0;

    struct bpf_map *map = &__bpf_storage_smap.map;
    int key = 1;
    int bad_key = 9;
    int next = 0;
    u64 value = *vp;

    __bpf_storage_reset();

    BPF_PROVE(inode_storage_ptr(&__bpf_storage_inode) ==
              &__bpf_storage_blob.storage);
    BPF_PROVE(bpf_fd_inode_storage_lookup_elem(map, &bad_key) ==
              ERR_PTR(-EBADF));
    BPF_PROVE(bpf_fd_inode_storage_update_elem(map, &bad_key, &value, 0) ==
              -EBADF);
    BPF_PROVE(bpf_fd_inode_storage_delete_elem(map, &bad_key) == -EBADF);
    BPF_PROVE(notsupp_get_next_key(map, &key, &next) == -ENOTSUPP);
    BPF_PROVE(inode_storage_map_ops.map_get_next_key(map, &key, &next) ==
              -ENOTSUPP);
    BPF_PROVE(inode_storage_map_alloc(NULL) == map);

    BPF_PROVE(bpf_inode_storage_get(map, NULL, &value,
                                    BPF_LOCAL_STORAGE_GET_F_CREATE) == 0);
    BPF_PROVE(bpf_inode_storage_get(map, &__bpf_storage_inode, &value,
                                    2) == 0);
    BPF_PROVE(bpf_inode_storage_delete(map, NULL) == -EINVAL);

    __bpf_storage_inode.i_security = NULL;
    BPF_PROVE(inode_storage_ptr(&__bpf_storage_inode) == NULL);
    BPF_PROVE(inode_storage_lookup(&__bpf_storage_inode, map, true) ==
              NULL);
    BPF_PROVE(bpf_fd_inode_storage_lookup_elem(map, &key) == NULL);
    BPF_PROVE(bpf_fd_inode_storage_update_elem(map, &key, &value, 0) ==
              -EBADF);
    BPF_PROVE(inode_storage_delete(&__bpf_storage_inode, map) == -ENOENT);
    BPF_PROVE(bpf_inode_storage_delete(map, &__bpf_storage_inode) ==
              -ENOENT);
    BPF_PROVE(bpf_fd_inode_storage_delete_elem(map, &key) == -ENOENT);
    BPF_PROVE(bpf_inode_storage_get(map, &__bpf_storage_inode, &value,
                                    BPF_LOCAL_STORAGE_GET_F_CREATE) == 0);

    __bpf_storage_inode.i_security = &__bpf_storage_blob;
    __bpf_storage_blob.storage = NULL;
    BPF_PROVE(inode_storage_lookup(&__bpf_storage_inode, map, true) ==
              NULL);
    BPF_PROVE(bpf_inode_storage_get(map, &__bpf_storage_inode, &value,
                                    0) == 0);

    BPF_PROVE(inode_storage_map_ops.map_meta_equal(map, map));
    BPF_PROVE(inode_storage_map_ops.map_alloc_check(NULL) == 0);
    BPF_PROVE(inode_storage_map_ops.map_mem_usage(map) ==
              sizeof(__bpf_storage_smap) + sizeof(__bpf_storage_elem));
    BPF_PROVE(inode_storage_map_ops.map_owner_storage_ptr(
                  &__bpf_storage_inode) ==
              &__bpf_storage_blob.storage);
    BPF_PROVE(inode_storage_map_ops.map_check_btf(map, NULL, NULL, NULL) ==
              0);
    BPF_PROVE(bpf_inode_storage_get_proto.ret_type ==
              RET_PTR_TO_MAP_VALUE_OR_NULL);
    BPF_PROVE(bpf_inode_storage_get_proto.arg1_type == ARG_CONST_MAP_PTR);
    BPF_PROVE(bpf_inode_storage_get_proto.arg2_btf_id ==
              &bpf_inode_storage_btf_ids[0]);
    BPF_PROVE(bpf_inode_storage_delete_proto.ret_type == RET_INTEGER);
    BPF_PROVE(bpf_inode_storage_delete_proto.arg2_btf_id ==
              &bpf_inode_storage_btf_ids[0]);

    bpf_inode_storage_free(&__bpf_storage_inode);
    inode_storage_map_free(map);
    return (int)(value + next + key + bad_key);
