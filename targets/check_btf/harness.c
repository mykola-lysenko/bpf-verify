    /* check_btf: verifier-side validation of userspace BTF metadata.
     * Covers abnormal-return restrictions, func_info early validation,
     * func_info/subprog matching, line_info/subprog matching, and CO-RE
     * relocation bounds checks.
     */
    static struct bpf_insn insns[4];
    struct bpf_prog_aux aux = {};
    struct bpf_prog prog = {};
    struct bpf_subprog_info subprogs[2] = {};
    struct bpf_verifier_env env = {};
    union bpf_attr attr = {};
    bpfptr_t uattr = make_bpfptr(&attr, true);
    struct bpf_func_info funcs[2] = {};
    struct bpf_line_info lines[2] = {};
    struct bpf_core_relo relos[1] = {};
    int ret;

    prog.aux = &aux;
    prog.insnsi = insns;
    prog.len = 4;
    env.prog = &prog;
    env.subprog_info = subprogs;
    env.subprog_cnt = 2;
    subprogs[0].start = 0;
    subprogs[1].start = 2;
    insns[0].code = 1;
    insns[2].code = 1;

    /* No func/line info: subprogram LD_ABS/tail-call use must be rejected. */
    subprogs[1].has_ld_abs = true;
    BPF_ASSERT(bpf_check_btf_info_early(&env, &attr, uattr) == -EINVAL);
    subprogs[1].has_ld_abs = false;
    BPF_ASSERT(bpf_check_btf_info_early(&env, &attr, uattr) == 0);

    attr.prog_btf_fd = 1;
    attr.func_info = funcs;
    attr.func_info_cnt = 1;
    attr.func_info_rec_size = 4;
    BPF_ASSERT(bpf_check_btf_info_early(&env, &attr, uattr) == -EINVAL);

    funcs[0].insn_off = 0;
    funcs[0].type_id = 1;
    funcs[1].insn_off = 2;
    funcs[1].type_id = 1;
    lines[0].insn_off = 0;
    lines[0].file_name_off = 1;
    lines[0].line_off = 2;
    lines[0].line_col = 10 << 10;
    lines[1].insn_off = 2;
    lines[1].file_name_off = 1;
    lines[1].line_off = 2;
    lines[1].line_col = 20 << 10;
    relos[0].insn_off = 0;
    relos[0].type_id = 3;
    relos[0].access_str_off = 1;

    attr.func_info_cnt = 2;
    attr.func_info_rec_size = sizeof(funcs[0]);
    attr.func_info = funcs;
    attr.line_info_cnt = 2;
    attr.line_info_rec_size = sizeof(lines[0]);
    attr.line_info = lines;
    attr.core_relo_cnt = 1;
    attr.core_relo_rec_size = sizeof(relos[0]);
    attr.core_relos = relos;

    BPF_ASSERT(bpf_check_btf_info_early(&env, &attr, uattr) == 0);
    BPF_ASSERT(aux.btf != NULL);
    BPF_ASSERT(aux.func_info_cnt == 2);
    /* Keep the second-pass func_info records on verifier-tracked stack
     * memory. The early path intentionally exercises allocator-backed copies,
     * but check_btf_func() assumes that successful early validation already
     * proved type_id safety and dereferences the records directly.
     */
    aux.func_info = funcs;
    ret = bpf_check_btf_info(&env, &attr, uattr);
    BPF_ASSERT(ret == 0);
    BPF_ASSERT(aux.func_info_aux != NULL);
    BPF_ASSERT(aux.linfo != NULL);
    BPF_ASSERT(aux.nr_linfo == 2);
    BPF_ASSERT(subprogs[0].linfo_idx == 0);
    BPF_ASSERT(subprogs[1].linfo_idx == 1);
    BPF_ASSERT(subprogs[1].name != NULL);

    attr.line_info_rec_size = 4;
    BPF_ASSERT(bpf_check_btf_info(&env, &attr, uattr) == -EINVAL);
    attr.line_info_rec_size = sizeof(lines[0]);

    relos[0].insn_off = 1;
    BPF_ASSERT(bpf_check_btf_info(&env, &attr, uattr) == -EINVAL);

    return (int)(aux.func_info_cnt + aux.nr_linfo);
