    /* range_tree: BPF arena range allocator.
     *
     * The full public set/find/clear round-trip stores range_node pointers in
     * rbtrees backed by .bss allocator storage. The verifier loses pointer type
     * when those child pointers are loaded back from map-value memory, so this
     * harness keeps retrieval tests on stack-built nodes where pointer spills
     * remain tracked.
     *
     * Covered here:
     *   1. range_tree_init() creates an empty tree; range_tree_find() returns -ENOENT.
     *   2. rn_size() computes inclusive range length.
     *   3. range_tree_find() performs best-fit lookup over the range-size rbtree.
     *   4. range_tree_set() inserts the first public range using kmalloc_nolock().
     */
    struct range_tree rt;
    struct range_tree insert_rt;
    struct range_node big;
    struct range_node small;

    range_tree_init(&rt);
    BPF_ASSERT(range_tree_find(&rt, 1) == -ENOENT);

    big.rb_range_size.__rb_parent_color = RB_BLACK;
    big.rb_range_size.rb_left = 0;
    big.rb_range_size.rb_right = &small.rb_range_size;
    big.rn_start = 4;
    big.rn_last = 11;
    big.__rn_subtree_last = 11;

    small.rb_range_size.__rb_parent_color =
        (unsigned long)&big.rb_range_size + RB_RED;
    small.rb_range_size.rb_left = 0;
    small.rb_range_size.rb_right = 0;
    small.rn_start = 20;
    small.rn_last = 23;
    small.__rn_subtree_last = 23;

    rt.range_size_root.rb_root.rb_node = &big.rb_range_size;
    rt.range_size_root.rb_leftmost = &big.rb_range_size;

    BPF_ASSERT(rn_size(&big) == 8);
    BPF_ASSERT(rn_size(&small) == 4);
    BPF_ASSERT(range_tree_find(&rt, 4) == 20);
    BPF_ASSERT(range_tree_find(&rt, 5) == 4);
    BPF_ASSERT(range_tree_find(&rt, 9) == -ENOENT);

    __bpf_range_tree_used = 0;
    range_tree_init(&insert_rt);
    BPF_ASSERT(range_tree_set(&insert_rt, 0, 4) == 0);
    return 0;