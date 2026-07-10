#pragma clang attribute pop
#pragma clang attribute pop
#undef bpf_get_call_summary
static __attribute__((always_inline)) void __bpf_liveness_reset_at(struct arg_track *at)
{
    int i;

    for (i = 0; i < MAX_AT_TRACK_REGS; i++)
        at[i] = (struct arg_track){ .frame = ARG_NONE };
}
