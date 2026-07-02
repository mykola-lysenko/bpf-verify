#define bpf_mprog_attach static __inline __attribute__((always_inline)) bpf_mprog_attach
#define bpf_mprog_detach static __inline __attribute__((always_inline)) bpf_mprog_detach
#define bpf_mprog_query static __inline __attribute__((always_inline)) bpf_mprog_query
#pragma clang attribute push(__attribute__((always_inline)), apply_to=function)
