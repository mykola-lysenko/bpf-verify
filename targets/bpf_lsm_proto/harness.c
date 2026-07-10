    /* bpf_lsm_proto: nullable mmap_file BPF LSM hook signature. */
    struct file file = { .id = 1 };
    u32 errors = 0;

    errors |= bpf_lsm_mmap_file(NULL, 1, 2, 3) != 0;
    errors |= bpf_lsm_mmap_file(&file, 1, 2, 3) != 0;

    return (int)(errors + file.id);
