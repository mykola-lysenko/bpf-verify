    /* syscall_prove: syscall-side map flag, size, and capability invariants. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    __u64 choice = input ? *input : 0;
    struct btf_record empty_record = {};
    struct btf_record spin_record = { .fields = BPF_SPIN_LOCK };
    struct bpf_map map = { .record = &empty_record };
    union bpf_attr attr = {};
    char dst[BPF_OBJ_NAME_LEN];
    char small_dst[4];
    char valid_name[BPF_OBJ_NAME_LEN] = "Abc_123.foo";
    char invalid_name[BPF_OBJ_NAME_LEN] = "bad-name";
    char full_name[BPF_OBJ_NAME_LEN] = {
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
        'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
    };
    char empty_name[4] = "";
    u64 flags;
    u32 file_flags;
    int ret;
    int acc = 0;

    ret = bpf_obj_name_cpy(dst, valid_name, BPF_OBJ_NAME_LEN);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 11);
    BPF_ASSERT(dst[0] == 'A');
    BPF_ASSERT(dst[3] == '_');
    BPF_ASSERT(dst[4] == '1');
    BPF_ASSERT(dst[7] == '.');
    BPF_ASSERT(dst[11] == 0);
    BPF_ASSERT(dst[15] == 0);

    ret = bpf_obj_name_cpy(dst, invalid_name, BPF_OBJ_NAME_LEN);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    BPF_ASSERT(dst[0] == 'b');
    BPF_ASSERT(dst[1] == 'a');
    BPF_ASSERT(dst[2] == 'd');
    BPF_ASSERT(dst[3] == 0);
    BPF_ASSERT(dst[15] == 0);

    ret = bpf_obj_name_cpy(dst, full_name, BPF_OBJ_NAME_LEN);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    BPF_ASSERT(dst[0] == 'a');
    BPF_ASSERT(dst[15] == 'p');

    ret = bpf_obj_name_cpy(small_dst, empty_name, sizeof(empty_name));
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    BPF_ASSERT(small_dst[0] == 0);
    BPF_ASSERT(small_dst[3] == 0);

    ret = bpf_obj_name_cpy(small_dst, empty_name, 0);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    map.map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
    BPF_KEEP_SCALAR(map.map_type);
    BPF_PROVE(IS_FD_ARRAY(&map));
    BPF_PROVE(IS_FD_MAP(&map));
    map.map_type = BPF_MAP_TYPE_PROG_ARRAY;
    BPF_KEEP_SCALAR(map.map_type);
    BPF_PROVE(IS_FD_PROG_ARRAY(&map));
    BPF_PROVE(IS_FD_MAP(&map));
    map.map_type = BPF_MAP_TYPE_HASH_OF_MAPS;
    BPF_KEEP_SCALAR(map.map_type);
    BPF_PROVE(IS_FD_HASH(&map));
    BPF_PROVE(IS_FD_MAP(&map));
    map.map_type = BPF_MAP_TYPE_HASH;
    BPF_KEEP_SCALAR(map.map_type);
    BPF_PROVE(!IS_FD_MAP(&map));

    map.value_size = 5;
    BPF_KEEP_SCALAR(map.value_size);
    BPF_PROVE(bpf_map_value_size(&map, 0) == 5);
    BPF_PROVE(bpf_map_value_size(&map, BPF_F_CPU) == 5);
    map.map_type = BPF_MAP_TYPE_PERCPU_HASH;
    BPF_KEEP_SCALAR(map.map_type);
    BPF_PROVE(bpf_map_value_size(&map, 0) == 32);
    BPF_PROVE(bpf_map_value_size(&map, BPF_F_ALL_CPUS) == 5);
    map.map_type = BPF_MAP_TYPE_LRU_PERCPU_HASH;
    BPF_KEEP_SCALAR(map.map_type);
    BPF_PROVE(bpf_map_value_size(&map, 0) == 32);
    map.map_type = BPF_MAP_TYPE_PERCPU_ARRAY;
    BPF_KEEP_SCALAR(map.map_type);
    BPF_PROVE(bpf_map_value_size(&map, 0) == 32);
    map.map_type = BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE;
    BPF_KEEP_SCALAR(map.map_type);
    BPF_PROVE(bpf_map_value_size(&map, 0) == 32);
    map.map_type = BPF_MAP_TYPE_PROG_ARRAY;
    BPF_KEEP_SCALAR(map.map_type);
    BPF_PROVE(bpf_map_value_size(&map, 0) == sizeof(u32));
    map.map_type = BPF_MAP_TYPE_HASH_OF_MAPS;
    BPF_KEEP_SCALAR(map.map_type);
    BPF_PROVE(bpf_map_value_size(&map, 0) == sizeof(u32));

    BPF_PROVE(bpf_map_flags_retain_permanent(BPF_F_RDONLY |
              BPF_F_WRONLY | BPF_F_NUMA_NODE) == BPF_F_NUMA_NODE);
    BPF_PROVE(bpf_map_flags_retain_permanent(0) == 0);

    file_flags = 0;
    BPF_KEEP_SCALAR(file_flags);
    ret = bpf_get_file_flag(file_flags);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == O_RDWR);
    file_flags = BPF_F_RDONLY;
    BPF_KEEP_SCALAR(file_flags);
    ret = bpf_get_file_flag(file_flags);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == O_RDONLY);
    file_flags = BPF_F_WRONLY;
    BPF_KEEP_SCALAR(file_flags);
    ret = bpf_get_file_flag(file_flags);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == O_WRONLY);
    file_flags = BPF_F_RDONLY | BPF_F_WRONLY;
    BPF_KEEP_SCALAR(file_flags);
    ret = bpf_get_file_flag(file_flags);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    file_flags = BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG;
    BPF_KEEP_SCALAR(file_flags);
    ret = bpf_get_file_flag(file_flags);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == O_RDWR);

    attr.map_type = BPF_MAP_TYPE_HASH;
    attr.key_size = 4;
    attr.value_size = 8;
    attr.max_entries = 16;
    attr.map_flags = BPF_F_RDONLY | BPF_F_WRONLY | BPF_F_NUMA_NODE;
    attr.numa_node = 2;
    attr.map_extra = 0x1234;
    BPF_KEEP_SCALAR(attr.map_type);
    BPF_KEEP_SCALAR(attr.key_size);
    BPF_KEEP_SCALAR(attr.value_size);
    BPF_KEEP_SCALAR(attr.max_entries);
    BPF_KEEP_SCALAR(attr.map_flags);
    BPF_KEEP_SCALAR(attr.numa_node);
    BPF_KEEP_SCALAR(attr.map_extra);
    bpf_map_init_from_attr(&map, &attr);
    BPF_ASSERT(map.map_type == BPF_MAP_TYPE_HASH);
    BPF_ASSERT(map.key_size == 4);
    BPF_ASSERT(map.value_size == 8);
    BPF_ASSERT(map.max_entries == 16);
    BPF_ASSERT(map.map_flags == BPF_F_NUMA_NODE);
    BPF_ASSERT(map.numa_node == 2);
    BPF_ASSERT(map.map_extra == 0x1234);

    attr.map_flags = BPF_F_RDONLY | BPF_F_WRONLY;
    BPF_KEEP_SCALAR(attr.map_flags);
    bpf_map_init_from_attr(&map, &attr);
    BPF_ASSERT(map.map_flags == 0);
    BPF_ASSERT(map.numa_node == NUMA_NO_NODE);

    attr.map_flags = 0;
    attr.numa_node = 3;
    BPF_KEEP_SCALAR(attr.map_flags);
    BPF_KEEP_SCALAR(attr.numa_node);
    BPF_PROVE(bpf_map_attr_numa_node(&attr) == NUMA_NO_NODE);
    attr.map_flags = BPF_F_NUMA_NODE;
    BPF_KEEP_SCALAR(attr.map_flags);
    BPF_PROVE(bpf_map_attr_numa_node(&attr) == 3);

    BPF_PROVE(!btf_record_has_field(&empty_record, BPF_SPIN_LOCK));
    BPF_PROVE(btf_record_has_field(&spin_record, BPF_SPIN_LOCK));
    BPF_PROVE(syscall_isalnum('0'));
    BPF_PROVE(syscall_isalnum('Z'));
    BPF_PROVE(syscall_isalnum('a'));
    BPF_PROVE(!syscall_isalnum('-'));

    map.map_type = BPF_MAP_TYPE_HASH;
    map.record = &empty_record;
    BPF_KEEP_SCALAR(map.map_type);
    ret = bpf_map_check_op_flags(&map, 0, BPF_F_LOCK | BPF_F_CPU);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = bpf_map_check_op_flags(&map, BPF_F_ALL_CPUS, BPF_F_LOCK);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    ret = bpf_map_check_op_flags(&map, BPF_F_LOCK, BPF_F_LOCK);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    map.record = &spin_record;
    ret = bpf_map_check_op_flags(&map, BPF_F_LOCK, BPF_F_LOCK);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    flags = 1ULL << 32;
    BPF_KEEP_SCALAR(flags);
    ret = bpf_map_check_op_flags(&map, flags, ~0ULL);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    ret = bpf_map_check_op_flags(&map, BPF_F_CPU, ~0ULL);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    map.map_type = BPF_MAP_TYPE_PERCPU_ARRAY;
    map.record = &empty_record;
    BPF_KEEP_SCALAR(map.map_type);
    flags = (2ULL << 32) | BPF_F_CPU;
    BPF_KEEP_SCALAR(flags);
    ret = bpf_map_check_op_flags(&map, flags, ~0ULL);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    flags = (4ULL << 32) | BPF_F_CPU;
    BPF_KEEP_SCALAR(flags);
    ret = bpf_map_check_op_flags(&map, flags, ~0ULL);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -ERANGE);
    ret = bpf_map_check_op_flags(&map, BPF_F_CPU | BPF_F_ALL_CPUS, ~0ULL);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);
    ret = bpf_map_check_op_flags(&map, BPF_F_ALL_CPUS, ~0ULL);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = bpf_map_check_op_flags(&map, BPF_F_ALL_CPUS, BPF_F_LOCK);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EINVAL);

    BPF_PROVE(bpf_map_supports_cpu_flags(BPF_MAP_TYPE_PERCPU_HASH));
    BPF_PROVE(bpf_map_supports_cpu_flags(BPF_MAP_TYPE_LRU_PERCPU_HASH));
    BPF_PROVE(bpf_map_supports_cpu_flags(BPF_MAP_TYPE_PERCPU_ARRAY));
    BPF_PROVE(bpf_map_supports_cpu_flags(BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE));
    BPF_PROVE(!bpf_map_supports_cpu_flags(BPF_MAP_TYPE_HASH));

    BPF_PROVE(is_net_admin_prog_type(BPF_PROG_TYPE_SCHED_CLS));
    BPF_PROVE(is_net_admin_prog_type(BPF_PROG_TYPE_XDP));
    BPF_PROVE(is_net_admin_prog_type(BPF_PROG_TYPE_CGROUP_SOCKOPT));
    BPF_PROVE(is_net_admin_prog_type(BPF_PROG_TYPE_NETFILTER));
    BPF_PROVE(is_net_admin_prog_type(BPF_PROG_TYPE_EXT));
    BPF_PROVE(!is_net_admin_prog_type(BPF_PROG_TYPE_CGROUP_SKB));
    BPF_PROVE(!is_net_admin_prog_type(BPF_PROG_TYPE_SK_REUSEPORT));
    BPF_PROVE(!is_net_admin_prog_type(BPF_PROG_TYPE_SOCKET_FILTER));
    BPF_PROVE(!is_net_admin_prog_type(BPF_PROG_TYPE_KPROBE));

    BPF_PROVE(is_perfmon_prog_type(BPF_PROG_TYPE_KPROBE));
    BPF_PROVE(is_perfmon_prog_type(BPF_PROG_TYPE_TRACEPOINT));
    BPF_PROVE(is_perfmon_prog_type(BPF_PROG_TYPE_PERF_EVENT));
    BPF_PROVE(is_perfmon_prog_type(BPF_PROG_TYPE_RAW_TRACEPOINT));
    BPF_PROVE(is_perfmon_prog_type(BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE));
    BPF_PROVE(is_perfmon_prog_type(BPF_PROG_TYPE_TRACING));
    BPF_PROVE(is_perfmon_prog_type(BPF_PROG_TYPE_LSM));
    BPF_PROVE(is_perfmon_prog_type(BPF_PROG_TYPE_STRUCT_OPS));
    BPF_PROVE(is_perfmon_prog_type(BPF_PROG_TYPE_EXT));
    BPF_PROVE(!is_perfmon_prog_type(BPF_PROG_TYPE_XDP));
    BPF_PROVE(!is_perfmon_prog_type(BPF_PROG_TYPE_SOCKET_FILTER));

    BPF_PROVE(syscall_map_create_cap(BPF_MAP_TYPE_HASH) ==
              SYSCALL_MAP_CAP_UNPRIV);
    BPF_PROVE(syscall_map_create_cap(BPF_MAP_TYPE_RINGBUF) ==
              SYSCALL_MAP_CAP_UNPRIV);
    BPF_PROVE(syscall_map_create_cap(BPF_MAP_TYPE_USER_RINGBUF) ==
              SYSCALL_MAP_CAP_UNPRIV);
    BPF_PROVE(syscall_map_create_cap(BPF_MAP_TYPE_CGRP_STORAGE) ==
              SYSCALL_MAP_CAP_BPF);
    BPF_PROVE(syscall_map_create_cap(BPF_MAP_TYPE_LPM_TRIE) ==
              SYSCALL_MAP_CAP_BPF);
    BPF_PROVE(syscall_map_create_cap(BPF_MAP_TYPE_STRUCT_OPS) ==
              SYSCALL_MAP_CAP_BPF);
    BPF_PROVE(syscall_map_create_cap(BPF_MAP_TYPE_ARENA) ==
              SYSCALL_MAP_CAP_BPF);
    BPF_PROVE(syscall_map_create_cap(BPF_MAP_TYPE_SOCKMAP) ==
              SYSCALL_MAP_CAP_NET_ADMIN);
    BPF_PROVE(syscall_map_create_cap(BPF_MAP_TYPE_XSKMAP) ==
              SYSCALL_MAP_CAP_NET_ADMIN);
    BPF_PROVE(syscall_map_create_cap(BPF_MAP_TYPE_DEVMAP_HASH) ==
              SYSCALL_MAP_CAP_NET_ADMIN);
    BPF_PROVE(syscall_map_create_cap(BPF_MAP_TYPE_UNSPEC) ==
              SYSCALL_MAP_CAP_UNSUPPORTED);
    BPF_PROVE(syscall_map_create_cap(__MAX_BPF_MAP_TYPE) ==
              SYSCALL_MAP_CAP_UNSUPPORTED);

    acc += ret + (int)choice + (int)flags;
    return acc;
