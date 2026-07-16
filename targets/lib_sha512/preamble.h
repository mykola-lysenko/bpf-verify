/* ctx + the input block in a map (keeps the 128-byte block and 64-byte state
 * off the harness stack). */
struct __bpf_sha512_data {
    struct sha512_ctx ctx;
    struct sha512_ctx ctx2;   /* second copy for the determinism check */
    u8 block[SHA512_BLOCK_SIZE];
};
struct {
    __uint(type, 1 /* BPF_MAP_TYPE_ARRAY */);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct __bpf_sha512_data);
} __bpf_sha512_map __attribute__((section(".maps"), used));
