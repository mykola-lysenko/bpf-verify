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
     *   5. Post-split interval/size tree invariants.
     *   6. Post-merge interval/size tree invariants.
     */
    struct range_tree rt;
    struct range_tree insert_rt;
    struct range_tree split_rt;
    struct range_tree merged_rt;
    struct range_node big;
    struct range_node small;
    struct range_node left = {};
    struct range_node right = {};
    struct range_node merged = {};

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

    range_tree_init(&split_rt);
    left.rn_rbnode.__rb_parent_color = RB_BLACK;
    left.rn_rbnode.rb_left = 0;
    left.rn_rbnode.rb_right = &right.rn_rbnode;
    left.rb_range_size.__rb_parent_color =
        (unsigned long)&right.rb_range_size + RB_RED;
    left.rb_range_size.rb_left = 0;
    left.rb_range_size.rb_right = 0;
    left.rn_start = 0;
    left.rn_last = 3;
    left.__rn_subtree_last = 15;

    right.rn_rbnode.__rb_parent_color =
        (unsigned long)&left.rn_rbnode + RB_RED;
    right.rn_rbnode.rb_left = 0;
    right.rn_rbnode.rb_right = 0;
    right.rb_range_size.__rb_parent_color = RB_BLACK;
    right.rb_range_size.rb_left = 0;
    right.rb_range_size.rb_right = &left.rb_range_size;
    right.rn_start = 8;
    right.rn_last = 15;
    right.__rn_subtree_last = 15;

    split_rt.it_root.rb_root.rb_node = &left.rn_rbnode;
    split_rt.it_root.rb_leftmost = &left.rn_rbnode;
    split_rt.range_size_root.rb_root.rb_node = &right.rb_range_size;
    split_rt.range_size_root.rb_leftmost = &right.rb_range_size;

    BPF_ASSERT(left.rn_start == 0);
    BPF_ASSERT(left.rn_last == 3);
    BPF_ASSERT(right.rn_start == 8);
    BPF_ASSERT(right.rn_last == 15);
    BPF_ASSERT(rn_size(&left) == 4);
    BPF_ASSERT(rn_size(&right) == 8);
    BPF_ASSERT(is_range_tree_set(&split_rt, 0, 4) == 0);
    BPF_ASSERT(is_range_tree_set(&split_rt, 4, 4) == -ESRCH);
    BPF_ASSERT(range_tree_find(&split_rt, 4) == 0);
    BPF_ASSERT(range_tree_find(&split_rt, 5) == 8);

    range_tree_init(&merged_rt);
    merged.rn_rbnode.__rb_parent_color = RB_BLACK;
    merged.rn_rbnode.rb_left = 0;
    merged.rn_rbnode.rb_right = 0;
    merged.rb_range_size.__rb_parent_color = RB_BLACK;
    merged.rb_range_size.rb_left = 0;
    merged.rb_range_size.rb_right = 0;
    merged.rn_start = 0;
    merged.rn_last = 15;
    merged.__rn_subtree_last = 15;

    merged_rt.it_root.rb_root.rb_node = &merged.rn_rbnode;
    merged_rt.it_root.rb_leftmost = &merged.rn_rbnode;
    merged_rt.range_size_root.rb_root.rb_node = &merged.rb_range_size;
    merged_rt.range_size_root.rb_leftmost = &merged.rb_range_size;

    BPF_ASSERT(rn_size(&merged) == 16);
    BPF_ASSERT(is_range_tree_set(&merged_rt, 0, 16) == 0);
    BPF_ASSERT(range_tree_find(&merged_rt, 16) == 0);
    BPF_ASSERT(range_tree_find(&merged_rt, 17) == -ENOENT);
    return 0;
