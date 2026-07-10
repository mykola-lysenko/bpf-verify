#undef inline
#define inline inline __attribute__((always_inline))
#include <linux/bpf_verifier.h>
#undef unlikely
#define unlikely(x) 0
#undef inline
#define inline inline __attribute__((always_inline))
