    /* bpf_cgrp_storage_prove: verifier-enforced cgroup storage invariants.
     *
     * The assert harness covers successful update/lookup/delete state changes.
     * This proof avoids volatile storage-presence reads and BSS pointer
     * IS_ERR() ambiguity, then proves guard paths and map/proto metadata.
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

    BPF_PROVE(cgroup_storage_ptr(&__bpf_storage_cgroup) ==
              &__bpf_storage_cgroup.bpf_cgrp_storage);
    BPF_PROVE(bpf_cgrp_storage_lookup_elem(map, &bad_key) ==
              ERR_PTR(-EBADF));
    BPF_PROVE(bpf_cgrp_storage_update_elem(map, &bad_key, &value, 0) ==
              -EBADF);
    BPF_PROVE(bpf_cgrp_storage_delete_elem(map, &bad_key) == -EBADF);
    BPF_PROVE(notsupp_get_next_key(map, &key, &next) == -ENOTSUPP);
    BPF_PROVE(cgrp_storage_map_ops.map_get_next_key(map, &key, &next) ==
              -ENOTSUPP);
    BPF_PROVE(cgroup_storage_map_alloc(NULL) == map);

    BPF_PROVE(bpf_cgrp_storage_get(map, NULL, &value,
                                   BPF_LOCAL_STORAGE_GET_F_CREATE) == 0);
    BPF_PROVE(bpf_cgrp_storage_get(map, &__bpf_storage_cgroup, &value,
                                   2) == 0);
    BPF_PROVE(bpf_cgrp_storage_delete(map, NULL) == -EINVAL);

    __bpf_storage_cgroup.bpf_cgrp_storage = NULL;
    BPF_PROVE(cgroup_storage_lookup(&__bpf_storage_cgroup, map, true) ==
              NULL);
    BPF_PROVE(cgroup_storage_delete(&__bpf_storage_cgroup, map) == -ENOENT);
    BPF_PROVE(bpf_cgrp_storage_delete(map, &__bpf_storage_cgroup) ==
              -ENOENT);
    BPF_PROVE(bpf_cgrp_storage_get(map, &__bpf_storage_cgroup, &value,
                                   0) == 0);
    __bpf_storage_cgroup.self.refcnt.dying = true;
    BPF_PROVE(bpf_cgrp_storage_get(map, &__bpf_storage_cgroup, &value,
                                   BPF_LOCAL_STORAGE_GET_F_CREATE) == 0);

    BPF_PROVE(cgrp_storage_map_ops.map_meta_equal(map, map));
    BPF_PROVE(cgrp_storage_map_ops.map_alloc_check(NULL) == 0);
    BPF_PROVE(cgrp_storage_map_ops.map_mem_usage(map) ==
              sizeof(__bpf_storage_smap) + sizeof(__bpf_storage_elem));
    BPF_PROVE(cgrp_storage_map_ops.map_owner_storage_ptr(
                  &__bpf_storage_cgroup) ==
              &__bpf_storage_cgroup.bpf_cgrp_storage);
    BPF_PROVE(cgrp_storage_map_ops.map_check_btf(map, NULL, NULL, NULL) ==
              0);
    BPF_PROVE(bpf_cgrp_storage_get_proto.ret_type ==
              RET_PTR_TO_MAP_VALUE_OR_NULL);
    BPF_PROVE(bpf_cgrp_storage_get_proto.arg1_type == ARG_CONST_MAP_PTR);
    BPF_PROVE(bpf_cgrp_storage_get_proto.arg2_btf_id ==
              &bpf_cgroup_btf_id[0]);
    BPF_PROVE(bpf_cgrp_storage_delete_proto.ret_type == RET_INTEGER);
    BPF_PROVE(bpf_cgrp_storage_delete_proto.arg2_btf_id ==
              &bpf_cgroup_btf_id[0]);

    bpf_cgrp_storage_free(&__bpf_storage_cgroup);
    cgroup_storage_map_free(map);
    return (int)(value + next + key + bad_key);
