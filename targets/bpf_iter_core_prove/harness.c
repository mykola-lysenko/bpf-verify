    /* bpf_iter core: direct-call-safe target and iterator metadata guards.
     * Callback-bearing paths (link attach/open/read/release) compile to BPF
     * callx, so this target keeps coverage on the non-indirect core helpers. */
    struct bpf_prog_aux aux = {};
    struct bpf_prog prog = {};
    struct bpf_prog new_prog = {};
    struct bpf_prog wrong_prog = {};
    struct bpf_iter_target_info tinfo = {};
    struct bpf_iter_link link = {};
    struct bpf_map_ops map_ops = {};
    struct bpf_map map = {};
    struct seq_file seq = {};
    u64 priv_storage[16] = {};
    struct bpf_iter_target_info *registered;
    struct bpf_iter_priv_data *priv = (struct bpf_iter_priv_data *)priv_storage;
    int ret;

    __bpf_iter_core_reset();
    INIT_LIST_HEAD(&targets);

    aux.attach_btf_id = 77;
    aux.attach_func_name = "bpf_iter_core";

    prog.aux = &aux;
    prog.type = 3;
    prog.expected_attach_type = 4;
    prog.sleepable = false;

    new_prog.aux = &aux;
    new_prog.type = 3;
    new_prog.expected_attach_type = 4;
    new_prog.sleepable = false;

    wrong_prog.aux = &aux;
    wrong_prog.type = 5;
    wrong_prog.expected_attach_type = 4;
    wrong_prog.sleepable = false;

    ret = bpf_iter_reg_target(&__bpf_iter_core_reg);
    BPF_ASSERT(ret == 0);
    BPF_ASSERT(__bpf_iter_core_allocs == 1);
    registered = (struct bpf_iter_target_info *)__bpf_iter_core_alloc_storage;
    BPF_ASSERT(registered->btf_id == 0);

    tinfo.reg_info = &__bpf_iter_core_reg;
    cache_btf_id(&tinfo, &prog);
    BPF_ASSERT(tinfo.btf_id == aux.attach_btf_id);
    BPF_ASSERT(bpf_iter_target_support_resched(&tinfo));
    tinfo.reg_info = &__bpf_iter_core_no_resched_reg;
    BPF_ASSERT(!bpf_iter_target_support_resched(&tinfo));
    tinfo.reg_info = &__bpf_iter_core_reg;

    link.tinfo = &tinfo;
    link.aux.map = NULL;
    BPF_ASSERT(__get_seq_info(&link) == &__bpf_iter_core_seq_info);
    map_ops.iter_seq_info = &__bpf_iter_core_alt_seq_info;
    map.ops = &map_ops;
    link.aux.map = &map;
    BPF_ASSERT(__get_seq_info(&link) == &__bpf_iter_core_alt_seq_info);
    link.aux.map = NULL;

    init_seq_meta(priv, &tinfo, &__bpf_iter_core_seq_info, &prog);
    BPF_ASSERT(priv->tinfo == &tinfo);
    BPF_ASSERT(priv->seq_info == &__bpf_iter_core_seq_info);
    BPF_ASSERT(priv->prog == &prog);
    BPF_ASSERT(priv->session_id != 0);
    BPF_ASSERT(priv->seq_num == 0);
    BPF_ASSERT(!priv->done_stop);

    seq.private = priv->target_private;
    BPF_ASSERT(bpf_iter_support_resched(&seq));
    bpf_iter_inc_seq_num(&seq);
    BPF_ASSERT(priv->seq_num == 1);
    bpf_iter_dec_seq_num(&seq);
    BPF_ASSERT(priv->seq_num == 0);
    bpf_iter_done_stop(&seq);
    BPF_ASSERT(priv->done_stop);

    link.link.prog = &prog;
    ret = bpf_iter_link_replace(&link.link, &new_prog, &wrong_prog);
    BPF_ASSERT(ret == -EPERM);
    ret = bpf_iter_link_replace(&link.link, &wrong_prog, &prog);
    BPF_ASSERT(ret == -EINVAL);
    ret = bpf_iter_link_replace(&link.link, &new_prog, &prog);
    BPF_ASSERT(ret == 0);
    BPF_ASSERT(link.link.prog == &new_prog);
    BPF_ASSERT(__bpf_iter_core_prog_puts == 1);

    prog.sleepable = false;
    ret = bpf_iter_run_prog(&prog, NULL);
    BPF_ASSERT(ret == 0);
    prog.sleepable = true;
    ret = bpf_iter_run_prog(&prog, NULL);
    BPF_ASSERT(ret == 0);
    prog.sleepable = false;

    return (int)(ret + priv->seq_num + __bpf_iter_core_allocs +
                 __bpf_iter_core_frees + __bpf_iter_core_prog_puts +
                 priv->done_stop);
