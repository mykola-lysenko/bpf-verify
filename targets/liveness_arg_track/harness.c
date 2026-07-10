    /* liveness_arg_track: arg_track state helpers.
     *
     * This covers struct-return helpers through target-local forced inlining,
     * avoiding the BPF backend's unsupported sret subprogram ABI, including
     * same-frame precise offset merge/dedup/overflow cases.
     */
    __u32 key = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &key);
    if (!vp) return 0;

    int ret = __bpf_liveness_arg_track_probe();

    BPF_ASSERT(ret == 44);
    return ret + (int)(*vp & 1);
