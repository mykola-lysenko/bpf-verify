/* Two Keccak states + the 200-byte seed in a map (off the harness stack). */
struct __bpf_sha3_data {
    u8 seed[SHA3_STATE_SIZE];
    struct sha3_state st1;
    struct sha3_state st2;
};
struct {
    __uint(type, 1 /* BPF_MAP_TYPE_ARRAY */);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct __bpf_sha3_data);
} __bpf_sha3_map __attribute__((section(".maps"), used));

/* __crypto_xor: used by sha3's absorb/squeeze XOR (unexercised here -- we drive
 * the raw permutation); real byte-wise implementation resolves the symbol. */
void __crypto_xor(u8 *dst, const u8 *src1, const u8 *src2, unsigned int size)
{ while (size--) *dst++ = *src1++ ^ *src2++; }
