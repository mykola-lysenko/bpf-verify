    /* mprog_prove: verifier-enforced mprog guard and helper invariants.
     *
     * The regular mprog harness covers public attach ordering. This proof
     * avoids pointer-identity assertions through fp_items because the verifier
     * does not reliably prune those false branches after pointer copies; it
     * instead proves scalar guard, count, revision, and release invariants.
     */
    struct bpf_mprog_bundle bundle;
    struct bpf_mprog_entry *entry;
    struct bpf_mprog_entry *entry_new = NULL;
    struct bpf_prog_aux aux0 = { .id = 20 };
    struct bpf_prog_aux aux1 = { .id = 21 };
    struct bpf_prog_aux aux2 = { .id = 22 };
    struct bpf_prog prog0 = {
        .aux = &aux0,
        .type = BPF_PROG_TYPE_SCHED_CLS,
    };
    struct bpf_prog prog1 = {
        .aux = &aux1,
        .type = BPF_PROG_TYPE_SCHED_CLS,
    };
    struct bpf_prog prog2 = {
        .aux = &aux2,
        .type = BPF_PROG_TYPE_SCHED_CLS,
    };
    struct bpf_link link0 = { .prog = &prog0 };
    struct bpf_tuple tuple0 = { .prog = &prog0, .link = NULL };
    struct bpf_tuple tuple1 = { .prog = &prog1, .link = NULL };
    struct bpf_tuple tuple2 = { .prog = &prog2, .link = NULL };
    struct bpf_tuple tuple_link = { .prog = NULL, .link = NULL };
    union bpf_attr attr = {};
    union bpf_attr uattr = {};
    u32 prog_ids[2] = {};
    u32 link_ids[2] = {};
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0;

    __bpf_mprog_reset();
    bpf_mprog_bundle_init(&bundle);
    entry = &bundle.a;

    BPF_PROVE(bpf_mprog_max() == 3);
    BPF_PROVE(bpf_mprog_total(entry) == 0);
    BPF_PROVE(bpf_mprog_revision(entry) == 1);
    BPF_PROVE(bpf_mprog_peer(&bundle.a) == &bundle.b);
    BPF_PROVE(bpf_mprog_peer(&bundle.b) == &bundle.a);

    BPF_PROVE(bpf_mprog_tuple_relative(&tuple_link, 0, 0,
                                        BPF_PROG_TYPE_SCHED_CLS) == 0);
    BPF_PROVE(tuple_link.prog == NULL && tuple_link.link == NULL);
    BPF_PROVE(bpf_mprog_tuple_relative(&tuple_link, 99, BPF_F_ID,
                                        BPF_PROG_TYPE_SCHED_CLS) == -ENOENT);
    BPF_PROVE(bpf_mprog_tuple_relative(&tuple_link, 9, BPF_F_LINK,
                                        BPF_PROG_TYPE_SCHED_CLS) == -EBADF);

    BPF_PROVE(bpf_mprog_attach(entry, &entry_new, &prog0, NULL,
                               NULL, 0, 0,
                               bpf_mprog_revision(entry) + 1) == -ESTALE);
    BPF_PROVE(bpf_mprog_detach(entry, &entry_new, NULL, NULL,
                               BPF_F_REPLACE, 0, 0) == -EINVAL);
    BPF_PROVE(bpf_mprog_detach(entry, &entry_new, NULL, NULL,
                               0, 0,
                               bpf_mprog_revision(entry) + 1) == -ESTALE);
    BPF_PROVE(bpf_mprog_detach(entry, &entry_new, NULL, NULL,
                               0, 0, 0) == -ENOENT);

    attr.query.query_flags = 1;
    BPF_PROVE(bpf_mprog_query(&attr, &uattr, entry) == -EINVAL);
    attr.query.query_flags = 0;
    attr.query.count = 2;
    attr.query.prog_ids = (u64)prog_ids;
    attr.query.link_ids = (u64)link_ids;
    BPF_PROVE(bpf_mprog_query(&attr, &uattr, entry) == 0);

    BPF_PROVE(bpf_mprog_insert(entry, &entry_new, &tuple0, 0, 0) == 0);
    BPF_PROVE(bpf_mprog_total(entry_new) == 1);
    entry = entry_new;

    BPF_PROVE(bpf_mprog_insert(entry, &entry_new, &tuple1, 1, 0) == 0);
    BPF_PROVE(bpf_mprog_total(entry_new) == 2);
    entry = entry_new;

    BPF_PROVE(bpf_mprog_replace(entry, &entry_new, &tuple2, 0) == 0);
    entry = entry_new;
    BPF_PROVE(bpf_mprog_total(entry) == 2);
    BPF_PROVE(entry->parent->ref == NULL);
    BPF_PROVE(bpf_mprog_fetch(entry, &tuple2, 0) == 0);

    tuple_link.prog = NULL;
    tuple_link.link = NULL;
    bundle.cp_items[0].link = &link0;
    BPF_PROVE(bpf_mprog_fetch(entry, &tuple_link, 0) == -EBUSY);
    bundle.cp_items[0].link = NULL;

    BPF_PROVE(bpf_mprog_delete(entry, &entry_new, &tuple2, 0) == 0);
    BPF_PROVE(bpf_mprog_total(entry_new) == 1);
    entry = entry_new;
    bpf_mprog_commit(entry);
    BPF_PROVE(entry->parent->ref == NULL);
    BPF_PROVE(bpf_mprog_revision(entry) == 2);

    return (int)(seed & 1);
