    /* gf128mul_x8_ble with dynamic input.  Avoid gf128mul_lle(): it uses
     * PTR_ALIGN() on a stack pointer, which BPF verifier rejects. */
    __u32 key = 0;
    __u64 *v = bpf_map_lookup_elem(&input_map, &key);
    if (!v) return 0;
    le128 x = { .a = cpu_to_le64(*v), .b = cpu_to_le64(*v >> 1) };
    le128 r;
    gf128mul_x8_ble(&r, &x);
    return (int)(le64_to_cpu(r.a) ^ le64_to_cpu(r.b));