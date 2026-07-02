    /* disasm: BPF instruction disassembler.
     *
     * print_bpf_insn() is built around a variadic callback (bpf_insn_print_t)
     * which the BPF backend cannot support (variadic functions and >5-arg calls
     * are both rejected).  We therefore verify the non-variadic parts of
     * disasm.c:
     *
     *   func_id_name(id)   -- array lookup: returns the string name of a BPF
     *                         helper function ID, or "unknown" for invalid IDs.
     *   bpf_class_string[] -- string table for BPF instruction classes.
     *   bpf_alu_string[]   -- string table for ALU operations.
     *
     * Properties verified:
     *   1. func_id_name(known_id) != NULL  (no null entry for valid helpers)
     *   2. func_id_name(-1) != NULL        (out-of-range returns "unknown")
     *   3. func_id_name(0) != NULL         (BPF_FUNC_unspec is valid)
     *   4. bpf_class_string[BPF_LD >> 0] != NULL
     *   5. bpf_alu_string[BPF_ADD >> 4] != NULL
     */

    /* 1. Known helper ID returns non-NULL name */
    BPF_ASSERT(func_id_name(BPF_FUNC_map_lookup_elem) != 0);

    /* 2. Out-of-range ID returns "unknown" (non-NULL) */
    BPF_ASSERT(func_id_name(-1) != 0);

    /* 3. BPF_FUNC_unspec (id=0) returns non-NULL */
    BPF_ASSERT(func_id_name(0) != 0);

    /* 4. bpf_class_string table is populated for BPF_LD class */
    BPF_ASSERT(bpf_class_string[BPF_LD] != 0);

    /* 5. bpf_alu_string table is populated for BPF_ADD operation */
    BPF_ASSERT(bpf_alu_string[BPF_ADD >> 4] != 0);

    return 0;