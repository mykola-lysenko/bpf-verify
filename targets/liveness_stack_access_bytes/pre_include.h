#include <linux/bpf_verifier.h>
/* Override helper/kfunc byte queries for record_arg_access() coverage. */
#define bpf_helper_stack_access_bytes(env, insn, arg_idx, insn_idx)     ((void)(env), (void)(insn), (void)(arg_idx), (void)(insn_idx), 8)
#define bpf_kfunc_stack_access_bytes(env, insn, arg_idx, insn_idx)     ((void)(env), (void)(insn), (void)(arg_idx), (void)(insn_idx), -8)
#pragma clang attribute push(__attribute__((always_inline)), apply_to=function)
