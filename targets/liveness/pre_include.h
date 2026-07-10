#include <linux/bpf_verifier.h>
/* Keep record_call_access() on the default 5-register-arg path so its loop
 * remains verifier-bounded after inlining. */
#define bpf_get_call_summary(env, insn, cs) false
#pragma clang attribute push(__attribute__((always_inline)), apply_to=function)
