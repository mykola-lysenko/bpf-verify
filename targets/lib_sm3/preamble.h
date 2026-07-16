struct __bpf_sm3_data {
    struct sm3_block_state st1;
    struct sm3_block_state st2;
    u8 block[SM3_BLOCK_SIZE];
    u32 W[16];
};
struct {
    __uint(type, 1);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct __bpf_sm3_data);
} __bpf_sm3_map __attribute__((section(".maps"), used));
