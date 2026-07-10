    /* log: verifier log bookkeeping and formatting helpers.
     * Covers attribute validation/init/finalize, log reset/alignment,
     * string conversion helpers, and the byte-reversal primitive used by
     * ring-buffer log finalization.
     */
    struct bpf_verifier_log log = {};
    struct bpf_verifier_env env = {};
    struct bpf_log_attr attr = {};
    struct bpf_common_attr common = {};
    struct bpf_reg_state reg = {};
    bpfptr_t bpfptr = {};
    struct tnum t = {};
    char buf[4] = { 'a', 'b', 'c', 'd' };
    char ws[4] = { ' ', '	', 'x', 0 };
    char tn[32] = {};
    const char *s;
    u32 actual = 123;

    BPF_ASSERT(bpf_vlog_init(&log, 0, NULL, 0) == 0);
    BPF_ASSERT(log.level == 0);
    BPF_ASSERT(log.ubuf == NULL);
    BPF_ASSERT(log.len_total == 0);

    BPF_ASSERT(bpf_vlog_init(&log, BPF_LOG_LEVEL1, NULL, 16) == -EINVAL);
    BPF_ASSERT(bpf_vlog_init(&log, BPF_LOG_LEVEL1, (char __user *)1, 16) == 0);
    BPF_ASSERT(log.level == BPF_LOG_LEVEL1);
    BPF_ASSERT(log.len_total == 16);

    log.ubuf = NULL;
    log.len_total = 0;
    log.level = BPF_LOG_LEVEL1;
    log.start_pos = 1;
    log.end_pos = 4;
    log.len_max = 9;
    bpf_vlog_reset(&log, 2);
    BPF_ASSERT(log.start_pos == 1);
    BPF_ASSERT(log.end_pos == 2);
    BPF_ASSERT(bpf_vlog_finalize(&log, &actual) == 0);
    BPF_ASSERT(actual == 9);

    BPF_ASSERT(bpf_vlog_alignment(0) == 39);
    BPF_ASSERT(bpf_vlog_alignment(39) == 8);

    bpf_vlog_reverse_kbuf(buf, sizeof(buf));
    BPF_ASSERT(buf[0] == 'd');
    BPF_ASSERT(buf[3] == 'a');
    BPF_ASSERT(*ltrim(ws) == 'x');

    BPF_ASSERT(dynptr_type_str(BPF_DYNPTR_TYPE_LOCAL)[0] == 'l');
    BPF_ASSERT(dynptr_type_str(BPF_DYNPTR_TYPE_RINGBUF)[0] == 'r');
    BPF_ASSERT(iter_state_str(BPF_ITER_STATE_ACTIVE)[0] == 'a');
    BPF_ASSERT(iter_state_str(BPF_ITER_STATE_DRAINED)[0] == 'd');

    reg.type = PTR_TO_MEM | MEM_RDONLY | PTR_MAYBE_NULL;
    s = reg_type_str(&env, reg.type);
    BPF_ASSERT(s == env.tmp_str_buf);
    BPF_ASSERT(type_is_map_ptr(CONST_PTR_TO_MAP));
    BPF_ASSERT(!type_is_map_ptr(PTR_TO_CTX));

    t.value = 42;
    BPF_ASSERT(tnum_strn(tn, sizeof(tn), t) == 0);

    BPF_ASSERT(bpf_log_attr_init(&attr, 0, 0, 0, 4, bpfptr, &common,
                                 bpfptr, sizeof(common)) == 0);
    BPF_ASSERT(attr.ubuf == NULL);
    BPF_ASSERT(attr.size == 0);
    log.level = 0;
    BPF_ASSERT(bpf_log_attr_finalize(&attr, &log) == 0);

    return (int)(actual + buf[0] + env.tmp_str_buf[0]);
