    /* mprog: multiprogram attach, replace, relative insert, detach, query,
     * and link/prog reference release paths. */
    struct bpf_mprog_bundle bundle;
    struct bpf_mprog_entry *entry;
    struct bpf_mprog_entry *entry_new = NULL;
    union bpf_attr attr = {};
    union bpf_attr uattr = {};
    u32 prog_ids[4] = {};
    u32 link_ids[4] = {};
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0;
    int ret;
    u32 errors = 0;

    __bpf_mprog_reset();
    bpf_mprog_bundle_init(&bundle);
    entry = &bundle.a;

    ret = bpf_mprog_attach(entry, &entry_new, &__bpf_mprog_prog0, NULL,
                           NULL, 0, 0, 0);
    errors |= ret != 0;
    if (!ret && entry != entry_new) {
        bpf_mprog_commit(entry);
        entry = entry_new;
    }
    errors |= bpf_mprog_total(entry) != 1;

    ret = bpf_mprog_attach(entry, &entry_new, &__bpf_mprog_prog1, NULL,
                           NULL, BPF_F_AFTER | BPF_F_ID,
                           __bpf_mprog_prog0_aux.id, 0);
    errors |= ret != 0;
    if (!ret && entry != entry_new) {
        bpf_mprog_commit(entry);
        entry = entry_new;
    }
    errors |= bpf_mprog_total(entry) != 2;

    ret = bpf_mprog_attach(entry, &entry_new, &__bpf_mprog_prog2, NULL,
                           &__bpf_mprog_prog0, BPF_F_REPLACE, 0, 0);
    errors |= ret != 0;
    if (!ret)
        bpf_mprog_commit(entry);

    __bpf_mprog_link0.prog = &__bpf_mprog_prog3;
    ret = bpf_mprog_attach(entry, &entry_new, &__bpf_mprog_prog3,
                           &__bpf_mprog_link0, NULL, BPF_F_BEFORE,
                           0, 0);
    errors |= ret != 0;
    if (!ret && entry != entry_new) {
        bpf_mprog_commit(entry);
        entry = entry_new;
    }
    errors |= bpf_mprog_total(entry) != 3;

    ret = bpf_mprog_detach(entry, &entry_new, &__bpf_mprog_prog3,
                           &__bpf_mprog_link0, 0, 0, 0);
    errors |= ret != 0;
    if (!ret && entry != entry_new) {
        bpf_mprog_commit(entry);
        entry = entry_new;
    }
    errors |= bpf_mprog_total(entry) != 2;

    ret = bpf_mprog_detach(entry, &entry_new, NULL, NULL, 0, 0, 0);
    errors |= ret != 0;
    if (!ret && entry != entry_new) {
        bpf_mprog_commit(entry);
        entry = entry_new;
    }
    errors |= bpf_mprog_total(entry) != 1;

    attr.query.count = 2;
    attr.query.prog_ids = (u64)prog_ids;
    attr.query.link_ids = (u64)link_ids;
    errors |= bpf_mprog_query(&attr, &uattr, entry) != 0;
    attr.query.query_flags = 1;
    errors |= bpf_mprog_query(&attr, &uattr, entry) != -EINVAL;

    errors |= bpf_mprog_attach(entry, &entry_new, &__bpf_mprog_prog1, NULL,
                               NULL, 0, 0, bpf_mprog_revision(entry) + 1) !=
              -ESTALE;
    errors |= bpf_mprog_attach(entry, &entry_new, &__bpf_mprog_prog2, NULL,
                               NULL, 0, 0, 0) != -EEXIST;

    return (int)(errors + bpf_mprog_total(entry) +
                 __bpf_mprog_prog_puts + __bpf_mprog_link_puts +
                 __bpf_mprog_copies + (seed & 1));