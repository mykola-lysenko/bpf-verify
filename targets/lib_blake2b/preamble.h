struct __bpf_b2b_data {
    struct blake2b_ctx c1;
    struct blake2b_ctx c2;
    u8 block[BLAKE2B_BLOCK_SIZE];
};
struct {
    __uint(type, 1);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct __bpf_b2b_data);
} __bpf_b2b_map __attribute__((section(".maps"), used));
