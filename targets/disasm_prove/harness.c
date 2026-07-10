    /* disasm_prove: verifier-enforced disassembler helper invariants.
     *
     * Dynamic string-table pointer dereferences are avoided: this object keeps
     * string pointers in rodata relocations that libbpf leaves opaque to the
     * verifier. The proof therefore targets constant table entries plus the
     * opcode classifier helpers used by print_bpf_insn().
     */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    __u64 choice = input ? *input : 0;
    int acc = 0;

    BPF_PROVE(func_id_name(BPF_FUNC_map_lookup_elem) != NULL);
    BPF_PROVE(func_id_name(-1) != NULL);
    BPF_PROVE(bpf_class_string[BPF_ALU64] != NULL);
    BPF_PROVE(bpf_alu_string[BPF_END >> 4] != NULL);

    struct bpf_insn insn = {};
    insn.code = BPF_ALU64 | ((choice & 1) ? BPF_DIV : BPF_MOD) | BPF_X;
    insn.off = (choice & 2) ? 1 : 0;
    if (insn.off == 1)
        BPF_PROVE(is_sdiv_smod(&insn));
    else
        BPF_PROVE(!is_sdiv_smod(&insn));
    acc += is_sdiv_smod(&insn);

    insn.code = BPF_ALU64 | BPF_MOV | BPF_X;
    if (choice & 4)
        insn.off = 8;
    else if (choice & 8)
        insn.off = 16;
    else
        insn.off = 0;
    if (insn.off == 8 || insn.off == 16)
        BPF_PROVE(is_movsx(&insn));
    else
        BPF_PROVE(!is_movsx(&insn));
    acc += is_movsx(&insn);

    insn.off = (choice & 16) ? BPF_ADDR_SPACE_CAST : BPF_ADDR_PERCPU;
    if (insn.off == BPF_ADDR_SPACE_CAST)
        BPF_PROVE(is_addr_space_cast(&insn));
    else
        BPF_PROVE(is_mov_percpu_addr(&insn));
    acc += is_addr_space_cast(&insn);
    acc += is_mov_percpu_addr(&insn);

    return (int)choice + acc;
