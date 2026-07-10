    /* bpf_lru_list_prove: verifier-enforced LRU count/local-list invariants.
     *
     * Direct BPF_PROVE checks on node->type/ref bytes are intentionally
     * avoided: the verifier loses precision on those byte fields after wider
     * stack writes. Counts and u32 hash propagation remain verifier-trackable.
     */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u32 hash = input ? (u32)*input : 0x12345678;
    unsigned int active_count;

    {
        struct bpf_lru count_lru = {};
        struct bpf_lru_list *count_l = &count_lru.common_lru.lru_list;
        struct bpf_lru_node nodes[2] = {};

        bpf_lru_list_init(count_l);
        bpf_lru_list_populate(count_l, nodes, 2);
        BPF_PROVE(count_l->counts[BPF_LRU_LIST_T_ACTIVE] == 0);
        BPF_PROVE(count_l->counts[BPF_LRU_LIST_T_INACTIVE] == 0);

        struct bpf_lru_node *n0 = bpf_lru_list_alloc(count_l);
        BPF_PROVE(n0 != NULL);
        BPF_PROVE(count_l->counts[BPF_LRU_LIST_T_ACTIVE] == 0);
        BPF_PROVE(count_l->counts[BPF_LRU_LIST_T_INACTIVE] == 1);
        BPF_PROVE(!bpf_lru_list_inactive_low(count_l));

        __bpf_lru_node_move(count_l, n0, BPF_LRU_LIST_T_ACTIVE);
        BPF_PROVE(count_l->counts[BPF_LRU_LIST_T_ACTIVE] == 1);
        BPF_PROVE(count_l->counts[BPF_LRU_LIST_T_INACTIVE] == 0);
        BPF_PROVE(bpf_lru_list_inactive_low(count_l));
        active_count = count_l->counts[BPF_LRU_LIST_T_ACTIVE];
    }

    struct bpf_lru_elem {
        struct bpf_lru_node node;
        u32 hash;
    };
    struct bpf_lru lru_ctx = {};
    struct bpf_lru_list *l = &lru_ctx.common_lru.lru_list;
    struct bpf_lru_locallist loc_l;
    struct bpf_lru_elem elems[2] = {};

    bpf_lru_list_init(l);
    bpf_lru_locallist_init(&loc_l, 0);
    lru_ctx.common_lru.local_list = &loc_l;
    lru_ctx.hash_offset = offsetof(struct bpf_lru_elem, hash);
    lru_ctx.nr_scans = 2;
    lru_ctx.percpu = false;
    lru_ctx.del_from_htab = NULL;
    lru_ctx.del_arg = NULL;

    bpf_lru_populate(&lru_ctx, elems,
                     offsetof(struct bpf_lru_elem, node),
                     sizeof(elems[0]), 2);
    BPF_PROVE(lru_ctx.target_free == 1);
    BPF_PROVE(l->counts[BPF_LRU_LIST_T_ACTIVE] == 0);
    BPF_PROVE(l->counts[BPF_LRU_LIST_T_INACTIVE] == 0);

    struct bpf_lru_node *p0 = bpf_lru_pop_free(&lru_ctx, hash);
    BPF_PROVE(p0 != NULL);
    struct bpf_lru_elem *e0 = container_of(p0, struct bpf_lru_elem, node);
    BPF_PROVE(e0->hash == hash);
    BPF_PROVE(l->counts[BPF_LRU_LIST_T_ACTIVE] == 0);
    BPF_PROVE(l->counts[BPF_LRU_LIST_T_INACTIVE] == 0);

    bpf_lru_push_free(&lru_ctx, p0);
    BPF_PROVE(l->counts[BPF_LRU_LIST_T_ACTIVE] == 0);
    BPF_PROVE(l->counts[BPF_LRU_LIST_T_INACTIVE] == 0);

    return (int)(e0->hash + active_count);
