struct __bpf_md5_data {
    struct md5_block_state st1;
    struct md5_block_state st2;
    u8 block[MD5_BLOCK_SIZE];
};
struct {
    __uint(type, 1);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct __bpf_md5_data);
} __bpf_md5_map __attribute__((section(".maps"), used));
