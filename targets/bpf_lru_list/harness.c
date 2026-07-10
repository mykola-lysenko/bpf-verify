    /* bpf_lru_list: BPF LRU list -- active/inactive/free list management.
     *
     * The BPF LRU list maintains three lists (active, inactive, free) and
     * two local lists (free, pending) for per-CPU caching. The core
     * invariants are:
     *
     *   1. After populating N nodes into the free list, the free list
     *      contains exactly N nodes and counts are zero.
     *   2. After moving a node from free to inactive, the inactive count
     *      increments by 1.
     *   3. After moving a node from inactive to active, the active count
     *      increments and inactive count decrements.
     *   4. After rotate_active: nodes with ref=0 move to inactive;
     *      nodes with ref=1 stay active (ref cleared).
     *   5. list_head prev/next links remain coherent across moves,
     *      rotations, shrink, and local free/pending transitions.
     *   6. bpf_lru_list_inactive_low() returns true iff
     *      inactive_count < active_count.
     *
     * We use a small static pool and a single bpf_lru_list.
     * No per-CPU infrastructure is needed.
     */
    struct bpf_lru lru_ctx = {};
    struct bpf_lru_list *l = &lru_ctx.common_lru.lru_list;
    bpf_lru_list_init(l);
    lru_ctx.nr_scans = 3;
    lru_ctx.del_from_htab = NULL;
    lru_ctx.del_arg = NULL;

    /* Populate 3 free nodes */
    struct bpf_lru_node nodes[3];
    bpf_lru_list_populate(l, nodes, 3);

    /* Invariant 1: free list has 3 nodes, counts are 0 */
    BPF_ASSERT(!list_empty(&l->lists[BPF_LRU_LIST_T_FREE]));
    BPF_ASSERT(l->counts[BPF_LRU_LIST_T_ACTIVE]   == 0);
    BPF_ASSERT(l->counts[BPF_LRU_LIST_T_INACTIVE] == 0);

    /* Allocate 3 nodes -> inactive */
    struct bpf_lru_node *n0 = bpf_lru_list_alloc(l);
    struct bpf_lru_node *n1 = bpf_lru_list_alloc(l);
    struct bpf_lru_node *n2 = bpf_lru_list_alloc(l);
    BPF_ASSERT(n0 != NULL && n1 != NULL && n2 != NULL);

    /* Invariant 2: inactive count == 3 */
    BPF_ASSERT(l->counts[BPF_LRU_LIST_T_INACTIVE] == 3);
    BPF_ASSERT(l->counts[BPF_LRU_LIST_T_ACTIVE]   == 0);

    /* Move n0 from inactive to active */
    __bpf_lru_node_move(l, n0, BPF_LRU_LIST_T_ACTIVE);

    /* Invariant 3: active=1, inactive=2 */
    BPF_ASSERT(l->counts[BPF_LRU_LIST_T_ACTIVE]   == 1);
    BPF_ASSERT(l->counts[BPF_LRU_LIST_T_INACTIVE] == 2);

    /* Invariant 5: inactive_low = (2 < 1) = false */
    BPF_ASSERT(!bpf_lru_list_inactive_low(l));

    /* Move n1 and n2 to active too -> active=3, inactive=0 */
    __bpf_lru_node_move(l, n1, BPF_LRU_LIST_T_ACTIVE);
    __bpf_lru_node_move(l, n2, BPF_LRU_LIST_T_ACTIVE);
    BPF_ASSERT(l->counts[BPF_LRU_LIST_T_ACTIVE]   == 3);
    BPF_ASSERT(l->counts[BPF_LRU_LIST_T_INACTIVE] == 0);

    /* Invariant 5: inactive_low = (0 < 3) = true */
    BPF_ASSERT(bpf_lru_list_inactive_low(l));

    /* Set ref=1 on n0, leave n1 and n2 with ref=0.
     * After rotate_active (nr_scans=3):
     *   n0 (ref=1) -> stays active, ref cleared
     *   n1 (ref=0) -> moves to inactive
     *   n2 (ref=0) -> moves to inactive
     */
    bpf_lru_node_set_ref(n0);
    __bpf_lru_list_rotate_active(&lru_ctx, l);

    /* Invariant 4: active=1 (n0), inactive=2 (n1,n2), n0.ref=0 */
    BPF_ASSERT(l->counts[BPF_LRU_LIST_T_ACTIVE]   == 1);
    BPF_ASSERT(l->counts[BPF_LRU_LIST_T_INACTIVE] == 2);
    BPF_ASSERT(n0->ref == 0);

    /* Shrink one unreferenced inactive node back to the free list. */
    unsigned int shrunk = __bpf_lru_list_shrink(
        &lru_ctx, l, 1, &l->lists[BPF_LRU_LIST_T_FREE],
        BPF_LRU_LIST_T_FREE);
    BPF_ASSERT(shrunk == 1);
    BPF_ASSERT(n0 == &nodes[2] && n1 == &nodes[1] && n2 == &nodes[0]);
    BPF_ASSERT(n1->type == BPF_LRU_LIST_T_FREE);
    BPF_ASSERT(n2->type == BPF_LRU_LIST_T_INACTIVE);
    BPF_ASSERT(__bpf_lru_list_single(&l->lists[BPF_LRU_LIST_T_ACTIVE], n0));
    BPF_ASSERT(__bpf_lru_list_single(&l->lists[BPF_LRU_LIST_T_FREE], n1));
    BPF_ASSERT(__bpf_lru_list_single(&l->lists[BPF_LRU_LIST_T_INACTIVE], n2));
    BPF_ASSERT(l->counts[BPF_LRU_LIST_T_ACTIVE] == 1);
    BPF_ASSERT(l->counts[BPF_LRU_LIST_T_INACTIVE] == 1);

    /* Exercise the common-LRU local free/pending path. */
    struct bpf_lru_elem {
        struct bpf_lru_node node;
        u32 hash;
    };
    struct bpf_lru_locallist loc_l;
    struct bpf_lru_elem elems[2];
    bpf_lru_list_init(l);
    bpf_lru_locallist_init(&loc_l, 0);
    lru_ctx.common_lru.local_list = &loc_l;
    lru_ctx.hash_offset = offsetof(struct bpf_lru_elem, hash);
    lru_ctx.nr_scans = 2;
    lru_ctx.percpu = false;
    lru_ctx.del_from_htab = NULL;
    bpf_lru_populate(&lru_ctx, elems,
                     offsetof(struct bpf_lru_elem, node),
                     sizeof(elems[0]), 2);
    BPF_ASSERT(lru_ctx.target_free == 1);

    struct bpf_lru_node *p0 = bpf_lru_pop_free(&lru_ctx, 0x12345678);
    BPF_ASSERT(p0 != NULL);
    struct bpf_lru_elem *e0 =
        container_of(p0, struct bpf_lru_elem, node);
    BPF_ASSERT(p0->type == BPF_LRU_LOCAL_LIST_T_PENDING);
    BPF_ASSERT(e0->hash == 0x12345678);

    bpf_lru_push_free(&lru_ctx, p0);
    BPF_ASSERT(p0->type == BPF_LRU_LOCAL_LIST_T_FREE);

    p0 = bpf_lru_pop_free(&lru_ctx, 0x87654321);
    BPF_ASSERT(p0 != NULL);
    BPF_ASSERT(p0 == &elems[1].node);
    e0 = container_of(p0, struct bpf_lru_elem, node);
    BPF_ASSERT(p0->type == BPF_LRU_LOCAL_LIST_T_PENDING);
    BPF_ASSERT(e0->hash == 0x87654321);
    BPF_ASSERT(__bpf_lru_list_single(local_pending_list(&loc_l), p0));
    BPF_ASSERT(__bpf_lru_list_empty(local_free_list(&loc_l)));
    BPF_ASSERT(__bpf_lru_list_single(&l->lists[BPF_LRU_LIST_T_FREE],
                                     &elems[0].node));

    return (int)(l->counts[BPF_LRU_LIST_T_ACTIVE] +
                 l->counts[BPF_LRU_LIST_T_INACTIVE]);
