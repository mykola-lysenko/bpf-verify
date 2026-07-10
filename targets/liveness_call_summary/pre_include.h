#include <linux/bpf_verifier.h>
/* Force a two-stack-arg call summary for record_call_access() coverage. */
#define bpf_get_call_summary(env, insn, cs)     ((cs)->num_params = MAX_BPF_FUNC_REG_ARGS + 2, true)
#pragma clang attribute push(__attribute__((always_inline)), apply_to=function)
