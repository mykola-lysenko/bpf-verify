    /* percpu_freelist_prove: verifier-enforced freelist invariants.
     *
     * A symbolic branch selects one of two proof modes so the verifier checks
     * both paths independently:
     *   1. Explicit push/pop preserves LIFO links and drains to empty.
     *   2. populate(nr) creates exactly nr poppable elements for nr in [1, 4].
     */
    __u32 key = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &key);
    if (!vp) return 0;

    if (*vp & 0x10) {
        struct pcpu_freelist fl;
        struct pcpu_freelist_head head;
        struct pcpu_freelist_node push_nodes[2] = {};
        struct pcpu_freelist_node *p0 = &push_nodes[0];
        struct pcpu_freelist_node *p1 = &push_nodes[1];
        struct pcpu_freelist_node *n0, *n1, *n2;
        u32 two = (u32)(*vp & 1);

        __bpf_hide_ptr(p0);
        __bpf_hide_ptr(p1);
        raw_res_spin_lock_init(&head.lock);
        head.first = 0;
        fl.freelist = &head;

        BPF_PROVE(pcpu_freelist_pop(&fl) == 0);
        pcpu_freelist_push(&fl, p0);
        BPF_PROVE(head.first == p0);
        BPF_PROVE(p0->next == 0);
        if (two) {
            pcpu_freelist_push(&fl, p1);
            BPF_PROVE(head.first == p1);
            BPF_PROVE(p1->next == p0);
        }

        n0 = pcpu_freelist_pop(&fl);
        BPF_PROVE(n0 != 0);
        if (two)
            BPF_PROVE(head.first == p0);
        else
            BPF_PROVE(head.first == 0);
        n1 = pcpu_freelist_pop(&fl);
        if (two)
            BPF_PROVE(n1 != 0);
        else
            BPF_PROVE(n1 == 0);
        BPF_PROVE(head.first == 0);
        n2 = pcpu_freelist_pop(&fl);
        BPF_PROVE(n2 == 0);
        return (int)(two + (n0 != 0));
    } else {
        struct pcpu_freelist fl;
        struct pcpu_freelist_head head;
        struct pcpu_freelist_node nodes[4] = {};
        struct pcpu_freelist_node *n0, *n1, *n2, *n3, *n4;
        void *buf = nodes;
        u32 nr = (u32)((*vp >> 1) & 3) + 1;

        __bpf_hide_ptr(buf);
        raw_res_spin_lock_init(&head.lock);
        head.first = 0;
        fl.freelist = &head;

        if (nr == 1)
            pcpu_freelist_populate(&fl, buf, sizeof(nodes[0]), 1);
        else if (nr == 2)
            pcpu_freelist_populate(&fl, buf, sizeof(nodes[0]), 2);
        else if (nr == 3)
            pcpu_freelist_populate(&fl, buf, sizeof(nodes[0]), 3);
        else
            pcpu_freelist_populate(&fl, buf, sizeof(nodes[0]), 4);

        n0 = pcpu_freelist_pop(&fl);
        n1 = pcpu_freelist_pop(&fl);
        n2 = pcpu_freelist_pop(&fl);
        n3 = pcpu_freelist_pop(&fl);
        n4 = pcpu_freelist_pop(&fl);

        BPF_PROVE(n0 != 0);
        if (nr >= 2)
            BPF_PROVE(n1 != 0);
        else
            BPF_PROVE(n1 == 0);
        if (nr >= 3)
            BPF_PROVE(n2 != 0);
        else
            BPF_PROVE(n2 == 0);
        if (nr >= 4)
            BPF_PROVE(n3 != 0);
        else
            BPF_PROVE(n3 == 0);
        BPF_PROVE(n4 == 0);
        BPF_PROVE(head.first == 0);
        return (int)(nr + (n0 != 0));
    }
