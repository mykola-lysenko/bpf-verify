    /* backtrack_prove: verifier-enforced backtrack bitmask invariants.
     *
     * Use map-derived register/slot indexes so the proof covers a small
     * symbolic domain instead of only constant folding one fixed case.
     */
    __u32 key = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &key);
    if (!vp) return 0;

    struct bpf_verifier_env env = {};
    struct backtrack_state bt = { .env = &env };
    u32 reg = (u32)(*vp & 3) + BPF_REG_1;
    u32 slot = (u32)((*vp >> 2) & 3);
    u32 arg_slot = (u32)((*vp >> 4) & 3);

    bt_init(&bt, 0);
    BPF_PROVE(bt_empty(&bt));

    bt_set_reg(&bt, reg);
    BPF_PROVE(bt_is_reg_set(&bt, reg));
    BPF_PROVE(bt_frame_reg_mask(&bt, 0) == (1U << reg));
    bt_clear_reg(&bt, reg);
    BPF_PROVE(!bt_is_reg_set(&bt, reg));
    BPF_PROVE(bt_empty(&bt));

    bpf_bt_set_frame_slot(&bt, 0, slot);
    BPF_PROVE(bt_is_frame_slot_set(&bt, 0, slot));
    BPF_PROVE(bt_frame_stack_mask(&bt, 0) == (1ULL << slot));
    bt_clear_frame_slot(&bt, 0, slot);
    BPF_PROVE(!bt_is_frame_slot_set(&bt, 0, slot));
    BPF_PROVE(bt_empty(&bt));

    bt_set_frame_stack_arg_slot(&bt, 0, arg_slot);
    BPF_PROVE(bt_is_frame_stack_arg_slot_set(&bt, 0, arg_slot));
    BPF_PROVE(bt_stack_arg_mask(&bt) == (1U << arg_slot));
    bt_clear_frame_stack_arg_slot(&bt, 0, arg_slot);
    BPF_PROVE(!bt_is_frame_stack_arg_slot_set(&bt, 0, arg_slot));
    BPF_PROVE(bt_empty(&bt));

    BPF_PROVE(bt_subprog_enter(&bt) == 0);
    BPF_PROVE(bt.frame == 1);
    BPF_PROVE(bt_subprog_exit(&bt) == 0);
    BPF_PROVE(bt.frame == 0);

    return (int)(*vp & 1);
