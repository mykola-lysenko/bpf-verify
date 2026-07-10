struct __bpf_iter_core_priv {
    u32 limit;
};

static const struct bpf_iter_seq_info __bpf_iter_core_seq_info = {
    .seq_priv_size = sizeof(struct __bpf_iter_core_priv),
};

static const struct bpf_iter_seq_info __bpf_iter_core_alt_seq_info = {
    .seq_priv_size = sizeof(struct __bpf_iter_core_priv) + 4,
};

static const struct bpf_iter_reg __bpf_iter_core_reg = {
    .target = "core",
    .ctx_arg_info_size = 1,
    .feature = BPF_ITER_RESCHED,
    .ctx_arg_info = {
        { .offset = 0, .reg_type = ARG_ANYTHING },
    },
    .seq_info = &__bpf_iter_core_seq_info,
};

static const struct bpf_iter_reg __bpf_iter_core_no_resched_reg = {
    .target = "core_no_resched",
    .seq_info = &__bpf_iter_core_seq_info,
};

