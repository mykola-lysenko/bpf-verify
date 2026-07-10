    /* range_tree_prove: verifier-enforced range-tree scalar invariants.
     *
     * Keep the proof away from rb_to_range_node() traversal for now: embedded
     * rb-node pointer arithmetic loses too much stack-field precision for the
     * verifier to prove best-fit search outcomes. These properties still check
     * symbolic range sizing and empty-tree lookup behavior.
     */
    __u32 key = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &key);
    if (!vp) return 0;

    struct range_tree rt;
    struct range_node rn = {};
    u32 start = (u32)(*vp & 0xff);
    u32 len = (u32)((*vp >> 8) & 0x1f) + 1;

    rn.rn_start = start;
    rn.rn_last = start + len - 1;
    BPF_PROVE(rn_size(&rn) == len);

    range_tree_init(&rt);
    BPF_PROVE(range_tree_find(&rt, len) == -ENOENT);

    return (int)(*vp & 1);
