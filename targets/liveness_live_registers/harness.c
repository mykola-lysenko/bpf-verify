    /* liveness_live_registers: fixed-point register liveness over tiny
     * straight-line and branch/join programs. The full entry point also runs
     * the stack arg-access prepass, so this wrapper keeps register propagation
     * isolated and leaves arg_track coverage to liveness_arg_track.
     */
    __u32 key = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &key);
    if (!vp) return 0;

    int ret = __bpf_liveness_live_registers_probe();

    BPF_ASSERT(ret == 31);
    return ret + (int)(*vp & 1);
