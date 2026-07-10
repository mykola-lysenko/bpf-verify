    /* liveness_successors: bpf_insn_successors() opcode coverage.
     *
     * The wrapper keeps env/prog/aux on stack so pointer fields remain typed
     * across the bpf_insn_successors() subprogram call. The reusable successor
     * buffers live in .bss because the helper returns those pointers.
     */
    __u32 key = 0;
    __u64 *vp = bpf_map_lookup_elem(&input_map, &key);
    if (!vp) return 0;

    int ret = __bpf_liveness_successors_probe();

    BPF_ASSERT(ret == 15);
    return ret + (int)(*vp & 1);
