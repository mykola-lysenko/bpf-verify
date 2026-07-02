/* Rename ZSTD_initStack to give it internal_linkage, avoiding StructRet
 * rejection by the BPF backend. */
#define ZSTD_initStack __attribute__((internal_linkage)) __bpf_ZSTD_initStack
