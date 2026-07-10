    /* percpu_freelist: per-CPU free-list used by BPF map internals.
     *
     * The target-specific pre-include collapses the kernel per-CPU API to a
     * single CPU and stubs rqspinlock, so this harness exercises the actual
     * freelist data-structure transitions while staying verifier-trackable.
     *
     * Covered here:
     *   1. pcpu_freelist_init() success and allocator failure paths.
     *   2. pcpu_freelist_push()/pop() LIFO ordering and empty-pop behavior.
     *   3. pcpu_freelist_populate() with a bounded dynamic element count.
     */
    __u32 key0 = 0;
    __u64 *v = bpf_map_lookup_elem(&input_map, &key0);
    if (!v) return 0;

    struct pcpu_freelist init_fl;
    struct pcpu_freelist fl;
    struct pcpu_freelist_head head;
    struct pcpu_freelist_node nodes[4];
    struct pcpu_freelist_node *p0, *p1;
    struct pcpu_freelist_node *n0, *n1, *n2;
    int two = (int)(*v & 1);
    u32 nr = (u32)((*v & 3) + 1);
    int ret;

    __bpf_pcpu_allocated = (u32)two;
    ret = pcpu_freelist_init(&init_fl);
    __bpf_memory_barrier();
    if (two) {
        BPF_ASSERT(ret == -ENOMEM);
    } else {
        BPF_ASSERT(ret == 0);
        BPF_ASSERT(init_fl.freelist == &__bpf_pcpu_head);
        pcpu_freelist_destroy(&init_fl);
    }

    raw_res_spin_lock_init(&head.lock);
    head.first = 0;
    fl.freelist = &head;

    p0 = &nodes[0];
    p1 = &nodes[1];
    __bpf_hide_ptr(p0);
    __bpf_hide_ptr(p1);

    BPF_ASSERT(pcpu_freelist_pop(&fl) == 0);
    pcpu_freelist_push(&fl, p0);
    __bpf_memory_barrier();
    if (two) {
        pcpu_freelist_push(&fl, p1);
        __bpf_memory_barrier();
    }

    n0 = pcpu_freelist_pop(&fl);
    __bpf_memory_barrier();
    n1 = pcpu_freelist_pop(&fl);
    __bpf_memory_barrier();
    n2 = pcpu_freelist_pop(&fl);
    if (two) {
        BPF_ASSERT(n0 == p1);
        BPF_ASSERT(n1 == p0);
    } else {
        BPF_ASSERT(n0 == p0);
        BPF_ASSERT(n1 == 0);
    }
    BPF_ASSERT(n2 == 0);

    pcpu_freelist_populate(&fl, nodes, sizeof(nodes[0]), nr);
    __bpf_memory_barrier();
    n0 = pcpu_freelist_pop(&fl);
    BPF_ASSERT(n0 != 0);
    return two + nr + (n0 != 0);
