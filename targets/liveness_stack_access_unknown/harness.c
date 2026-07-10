    /* liveness_stack_access_unknown: S64_MIN stack-access semantics.
     *
     * Unknown-size helper/kfunc reads should conservatively mark every stack
     * slot from fp+0 through the known offset, and unknown offsets mark the
     * whole frame readable.
     */
    __u32 key = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &key);
    if (!vp) return 0;

    struct func_instance inst = {};
    struct per_frame_masks *masks;
    struct arg_track arg = {};

    inst.depth = 0;
    inst.subprog_start = 0;
    inst.insn_cnt = 2;

    BPF_ASSERT(record_stack_access_off(&inst, -24, S64_MIN, 0, 0) == 0);
    masks = get_frame_masks(&inst, 0, 0);
    BPF_ASSERT(masks && spis_equal(masks->may_read, (spis_t)0x3f) &&
               spis_is_zero(masks->must_write));

    arg = (struct arg_track){
        .frame = 0,
        .off_cnt = 0,
    };
    BPF_ASSERT(record_stack_access(&inst, &arg, S64_MIN, 0, 1) == 0);
    masks = get_frame_masks(&inst, 0, 1);
    BPF_ASSERT(masks && spis_equal(masks->may_read, SPIS_ALL) &&
               spis_is_zero(masks->must_write));

    return (int)(*vp & 1);
