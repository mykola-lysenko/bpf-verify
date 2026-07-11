    /* bpf_lsm_mmap_file: nullable BPF LSM hook. Seed args so the calls stay
     * live and both the NULL and non-NULL paths are observed. */
    __u32 k0 = 0, k1 = 1;
    __u64 *a = bpf_map_lookup_elem(&input_map, &k0);
    __u64 *b = bpf_map_lookup_elem(&input_map, &k1);
    unsigned long p = (unsigned long)(a ? *a : 0);
    struct file file = { .id = (int)(b ? *b : 1) };
    u32 errors = 0;
    errors |= bpf_lsm_mmap_file(NULL, p, p + 1, p + 2) != 0;
    errors |= bpf_lsm_mmap_file(&file, p, p + 1, p + 2) != 0;
    return (int)(errors + file.id);
