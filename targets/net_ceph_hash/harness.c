    /* net/ceph/ceph_hash.c: bounded string hash variants. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0x0102030405060708ULL;
    char name[16];
    int i;
    unsigned linux_hash;
    unsigned rjenkins_hash;
    unsigned dispatch_hash;
    unsigned bad_hash;

    for (i = 0; i < 16; i++)
        name[i] = 'a' + (char)((seed >> ((i & 7) * 8)) & 15);

    linux_hash = ceph_str_hash_linux(name, sizeof(name));
    rjenkins_hash = ceph_str_hash_rjenkins(name, sizeof(name));
    dispatch_hash = ceph_str_hash(CEPH_STR_HASH_RJENKINS, name, sizeof(name));
    bad_hash = ceph_str_hash(0, name, 4);

    return (int)(linux_hash ^ rjenkins_hash ^ dispatch_hash ^ bad_hash);
