/* Step 1: define renamed struct tags BEFORE the function-rename macros. */
struct __bpf_recip_rv  { unsigned int m; unsigned char sh1, sh2; };
struct __bpf_recip_rva { unsigned int m; unsigned char sh, exp; int is_wide_m; };
/* Step 2: rename functions and inject internal_linkage.
 * The macro expands in struct-tag positions too (e.g. 'struct reciprocal_value'
 * becomes 'struct __bpf_recip_rv'), but since we defined that tag above it is valid.
 * internal_linkage makes the StructRet functions acceptable to the BPF backend. */
#define reciprocal_value     __attribute__((internal_linkage)) __bpf_recip_rv
#define reciprocal_value_adv __attribute__((internal_linkage)) __bpf_recip_rva
/* Step 3: block reciprocal_div.h -- its struct definitions would conflict. */
#define _LINUX_RECIPROCAL_DIV_H
