    /* stream: stdout/stderr stream buffering and staged commit helpers. */
    struct bpf_prog_aux aux = {};
    struct bpf_prog prog = {};
    struct bpf_stream_stage stage = {};
    struct bpf_stream_elem elem;
    struct bpf_stream_elem stage_elem;
    char buf[8] = {};
    int ret;

    prog.aux = &aux;
    aux.prog = &prog;
    aux.main_prog_aux = &aux;

    bpf_prog_stream_init(&prog);
    BPF_ASSERT(atomic_read(&aux.stream[0].capacity) == 0);
    BPF_ASSERT(llist_empty(&aux.stream[0].log));
    BPF_ASSERT(bpf_prog_stream_read(&prog, 99, buf, sizeof(buf)) == -ENOENT);
    BPF_ASSERT(bpf_stream_vprintk(99, "bad", NULL, 0, &aux) == -ENOENT);
    BPF_ASSERT(bpf_stream_vprintk(BPF_STDOUT, "bad", NULL, 8, &aux) == -EINVAL);
    BPF_ASSERT(bpf_stream_vprintk(BPF_STDOUT, "bad", NULL, 4, &aux) == -EINVAL);

    /* Keep consumed_len as a 32-bit stack write; otherwise clang can combine
     * adjacent field stores and the verifier loses the field value. */
    init_llist_node(&elem.node);
    elem.total_len = 3;
    (*(volatile int *)&elem.consumed_len) = 0;
    elem.str[0] = 'a';
    elem.str[1] = 'b';
    elem.str[2] = 'c';
    llist_add(&elem.node, &aux.stream[0].log);
    atomic_set(&aux.stream[0].capacity, 3);
    BPF_ASSERT(atomic_read(&aux.stream[0].capacity) == 3);
    BPF_ASSERT(bpf_prog_stream_read(&prog, BPF_STDOUT, buf, 2) == 2);
    BPF_ASSERT(buf[0] == 'a');
    BPF_ASSERT(buf[1] == 'b');
    BPF_ASSERT(atomic_read(&aux.stream[0].capacity) == 3);

    aux.stream[0].backlog_head = NULL;
    aux.stream[0].backlog_tail = NULL;
    init_llist_head(&aux.stream[0].log);
    init_llist_node(&elem.node);
    elem.total_len = 3;
    (*(volatile int *)&elem.consumed_len) = 0;
    elem.str[0] = 'a';
    elem.str[1] = 'b';
    elem.str[2] = 'c';
    llist_add(&elem.node, &aux.stream[0].log);
    atomic_set(&aux.stream[0].capacity, 3);
    BPF_ASSERT(bpf_prog_stream_read(&prog, BPF_STDOUT, buf, 3) == 3);
    BPF_ASSERT(buf[2] == 'c');
    BPF_ASSERT(atomic_read(&aux.stream[0].capacity) == 0);

    atomic_set(&aux.stream[0].capacity, BPF_STREAM_MAX_CAPACITY);
    BPF_ASSERT(bpf_stream_vprintk(BPF_STDOUT, "z", NULL, 0, &aux) == -ENOSPC);
    atomic_set(&aux.stream[0].capacity, 0);

    bpf_stream_stage_init(&stage);
    init_llist_node(&stage_elem.node);
    stage_elem.total_len = 2;
    (*(volatile int *)&stage_elem.consumed_len) = 0;
    stage_elem.str[0] = 'x';
    stage_elem.str[1] = 'y';
    llist_add(&stage_elem.node, &stage.log);
    stage.len = 2;
    BPF_ASSERT(bpf_stream_stage_commit(&stage, &prog, BPF_STDERR) == 0);
    BPF_ASSERT(atomic_read(&aux.stream[1].capacity) == 2);
    BPF_ASSERT(bpf_prog_stream_read(&prog, BPF_STDERR, buf, sizeof(buf)) == 2);
    BPF_ASSERT(buf[0] == 'x');
    BPF_ASSERT(buf[1] == 'y');
    bpf_stream_stage_free(&stage);

    BPF_ASSERT(bpf_stream_print_stack(99, &aux) == -ENOENT);
    ret = bpf_stream_vprintk(BPF_STDOUT, "z", NULL, 0, &aux);
    BPF_ASSERT(ret == 0);

    bpf_prog_stream_free(&prog);
    return (int)(__bpf_stream_allocs + __bpf_stream_frees);
