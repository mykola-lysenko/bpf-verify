    /* range_tree_find_prove: symbolic best-fit search over a range-size tree.
     *
     * range_tree covers the public range_tree_find() entry point on fixed
     * stack-built rbtrees. This proof keeps the same best-fit policy symbolic
     * by using a target-local three-node wrapper: direct node references avoid
     * the verifier precision loss from rb_to_range_node() container-pointer
     * recovery while still proving the size-ordered search decisions.
     */
    __u32 key = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &key);
    if (!vp) return 0;

    struct range_tree rt;
    struct range_node root = {};
    struct range_node small = {};
    struct range_node large = {};
    u64 seed = *vp;
    u32 len = (u32)(seed & 0x1f) + 1;
    u32 root_start = (u32)((seed >> 8) & 0xff);
    u32 small_start = (u32)((seed >> 16) & 0xff) + 0x100;
    u32 large_start = (u32)((seed >> 24) & 0xff) + 0x200;
    s64 found;

    range_tree_init(&rt);
    root.rb_range_size.__rb_parent_color = RB_BLACK;
    root.rb_range_size.rb_left = &large.rb_range_size;
    root.rb_range_size.rb_right = &small.rb_range_size;
    root.rn_start = root_start;
    root.rn_last = root_start + 7;
    root.__rn_subtree_last = root.rn_last;

    small.rb_range_size.__rb_parent_color =
        (unsigned long)&root.rb_range_size + RB_RED;
    small.rn_start = small_start;
    small.rn_last = small_start + 3;
    small.__rn_subtree_last = small.rn_last;

    large.rb_range_size.__rb_parent_color =
        (unsigned long)&root.rb_range_size + RB_RED;
    large.rn_start = large_start;
    large.rn_last = large_start + 15;
    large.__rn_subtree_last = large.rn_last;

    rt.range_size_root.rb_root.rb_node = &root.rb_range_size;
    rt.range_size_root.rb_leftmost = &large.rb_range_size;

    BPF_PROVE(rn_size(&small) == 4);
    BPF_PROVE(rn_size(&root) == 8);
    BPF_PROVE(rn_size(&large) == 16);

    found = __bpf_range_tree_find_three(&rt, &root, &large, &small, len);
    BPF_PROVE(found != -EFAULT);

    if (len <= 4)
        BPF_PROVE(found == small_start);
    else if (len <= 8)
        BPF_PROVE(found == root_start);
    else if (len <= 16)
        BPF_PROVE(found == large_start);
    else
        BPF_PROVE(found == -ENOENT);

    return (int)(found ^ seed);
