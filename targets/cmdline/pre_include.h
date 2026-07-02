#define simple_strtoull __bpf_cmdline_simple_strtoull
#define simple_strtol __bpf_cmdline_simple_strtol
#define strlen __bpf_cmdline_strlen
#define strncmp __bpf_cmdline_strncmp
#define skip_spaces __bpf_cmdline_skip_spaces
#pragma clang attribute push(__attribute__((always_inline)), apply_to=function)
