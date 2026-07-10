    /* bpf_verification_stubs: verification-only tracing stubs.
     * Covers trace printk helper prototypes, generic tracing verifier ops,
     * tracing kfunc registration, signal-task validation, and callchain stubs.
     */
    struct bpf_prog prog = {};
    struct bpf_insn_access_aux aux = {};
    struct task_struct task = {};
    struct pt_regs regs = {};
    const struct bpf_func_proto *proto;
    int rctx = 7;

    BPF_ASSERT((s64)bpf_trace_printk(0, 0, 0, 0, 0) == -EOPNOTSUPP);
    proto = bpf_get_trace_printk_proto();
    BPF_ASSERT(proto->gpl_only);
    BPF_ASSERT(proto->ret_type == RET_INTEGER);
    BPF_ASSERT(proto->arg1_type == (ARG_PTR_TO_MEM | MEM_RDONLY));
    BPF_ASSERT(proto->arg2_type == ARG_CONST_SIZE);

    BPF_ASSERT((s64)bpf_trace_vprintk(0, 0, 0, 0, 0) == -EOPNOTSUPP);
    proto = bpf_get_trace_vprintk_proto();
    BPF_ASSERT(proto->gpl_only);
    BPF_ASSERT(proto->arg3_type ==
               (ARG_PTR_TO_MEM | PTR_MAYBE_NULL | MEM_RDONLY));
    BPF_ASSERT(proto->arg4_type == ARG_CONST_SIZE_OR_ZERO);

    proto = stub_tracing_func_proto(BPF_FUNC_unspec, &prog);
    BPF_ASSERT(proto->ret_type == RET_INTEGER);
    BPF_ASSERT(stub_tracing_is_valid_access(0, 4, BPF_READ, &prog, &aux));
    BPF_ASSERT(!stub_tracing_is_valid_access(-1, 4, BPF_READ, &prog, &aux));
    BPF_ASSERT(tracing_prog_ops.test_run(&prog) == 0);

    BPF_ASSERT((s64)bpf_send_signal_task(&task, 9, PIDTYPE_PID, 0) == -EOPNOTSUPP);
    BPF_ASSERT((s64)bpf_send_signal_task(&task, 9, PIDTYPE_TGID, 0) == -EOPNOTSUPP);
    BPF_ASSERT(bpf_send_signal_task(&task, 9, PIDTYPE_PGID, 0) == -EINVAL);
    BPF_ASSERT(tracing_stub_kfuncs_init() == 0);

    BPF_ASSERT(sysctl_perf_event_max_stack == PERF_MAX_STACK_DEPTH);
    BPF_ASSERT(get_callchain_buffers(8) == 0);
    put_callchain_buffers();
    BPF_ASSERT(get_callchain_entry(&rctx) == NULL);
    BPF_ASSERT(rctx == -1);
    put_callchain_entry(rctx);
    BPF_ASSERT(get_perf_callchain(&regs, true, false, 8, false, false, 0) == NULL);

    return (int)(proto->ret_type + rctx + sysctl_perf_event_max_stack);
