    /* dispatcher: program slot accounting and update allocation path.
     *
     * Covered here:
     *   1. bpf_dispatcher_add_prog()/remove_prog() refcount transitions.
     *   2. full-table rejection via bpf_dispatcher_find_free().
     *   3. bpf_dispatcher_prepare() arch fallback and change_prog() allocation.
     */
    struct bpf_dispatcher d = {};
    struct bpf_prog p0 = { .bpf_func = 0x1000 };
    struct bpf_prog p1 = { .bpf_func = 0x2000 };
    struct bpf_prog p2 = { .bpf_func = 0x3000 };
    struct bpf_prog p3 = { .bpf_func = 0x4000 };
    struct bpf_prog p4 = { .bpf_func = 0x5000 };

    __bpf_dispatcher_prog_incs = 0;
    __bpf_dispatcher_prog_puts = 0;
    __bpf_dispatcher_pack_allocated = 0;
    __bpf_dispatcher_exec_allocated = 0;

    BPF_ASSERT(!bpf_dispatcher_add_prog(&d, NULL));
    BPF_ASSERT(bpf_dispatcher_find_free(&d) == &d.progs[0]);
    BPF_ASSERT(bpf_dispatcher_add_prog(&d, &p0));
    BPF_ASSERT(d.num_progs == 1);
    BPF_ASSERT(d.progs[0].prog == &p0);
    BPF_ASSERT(d.progs[0].users.refs == 1);
    BPF_ASSERT(p0.refs == 1);
    BPF_ASSERT(__bpf_dispatcher_prog_incs == 1);

    BPF_ASSERT(!bpf_dispatcher_add_prog(&d, &p0));
    BPF_ASSERT(d.num_progs == 1);
    BPF_ASSERT(d.progs[0].users.refs == 2);
    BPF_ASSERT(p0.refs == 1);
    BPF_ASSERT(!bpf_dispatcher_remove_prog(&d, &p0));
    BPF_ASSERT(d.progs[0].users.refs == 1);
    BPF_ASSERT(d.num_progs == 1);
    BPF_ASSERT(bpf_dispatcher_remove_prog(&d, &p0));
    BPF_ASSERT(d.num_progs == 0);
    BPF_ASSERT(p0.refs == 0);
    BPF_ASSERT(__bpf_dispatcher_prog_puts == 1);

    BPF_ASSERT(bpf_dispatcher_add_prog(&d, &p0));
    BPF_ASSERT(bpf_dispatcher_add_prog(&d, &p1));
    BPF_ASSERT(bpf_dispatcher_add_prog(&d, &p2));
    BPF_ASSERT(bpf_dispatcher_add_prog(&d, &p3));
    BPF_ASSERT(d.num_progs == BPF_DISPATCHER_MAX);
    BPF_ASSERT(!bpf_dispatcher_add_prog(&d, &p4));
    BPF_ASSERT(p4.refs == 0);
    BPF_ASSERT(bpf_dispatcher_prepare(&d, __bpf_dispatcher_image,
                                      __bpf_dispatcher_rw_image) == -ENOTSUPP);

    BPF_ASSERT(bpf_dispatcher_remove_prog(&d, &p0));
    BPF_ASSERT(bpf_dispatcher_remove_prog(&d, &p1));
    BPF_ASSERT(bpf_dispatcher_remove_prog(&d, &p2));
    BPF_ASSERT(bpf_dispatcher_remove_prog(&d, &p3));
    BPF_ASSERT(d.num_progs == 0);

    bpf_dispatcher_change_prog(&d, NULL, &p0);
    BPF_ASSERT(d.image == __bpf_dispatcher_image);
    BPF_ASSERT(d.rw_image == __bpf_dispatcher_rw_image);
    BPF_ASSERT(d.num_progs == 1);
    BPF_ASSERT(p0.refs == 1);
    BPF_ASSERT(__bpf_dispatcher_pack_allocated == 1);
    BPF_ASSERT(__bpf_dispatcher_exec_allocated == 1);

    bpf_dispatcher_change_prog(&d, &p0, &p1);
    BPF_ASSERT(d.num_progs == 1);
    BPF_ASSERT(p0.refs == 0);
    BPF_ASSERT(p1.refs == 1);
    bpf_dispatcher_change_prog(&d, &p1, NULL);
    BPF_ASSERT(d.num_progs == 0);
    BPF_ASSERT(p1.refs == 0);

    return (int)(__bpf_dispatcher_prog_incs + __bpf_dispatcher_prog_puts);