/* Undef the rename macro so our wrapper is not renamed again. */
#undef sha256_blocks_generic
/* Provide a BPF-friendly sha256_blocks_generic that uses a static W[64] array
 * instead of a stack-allocated one.  The original (renamed to __bpf_sha256_blocks_orig)
 * puts W[64] = 256 bytes on the BPF stack; combined with the harness frame that
 * rounds up to 32+512 = 544 bytes, exceeding the 512-byte limit.
 * Using static W[64] reduces the stack to ~240 bytes (rounds up to 256),
 * giving a combined depth of 32+256 = 288 bytes. */
static void sha256_blocks_generic(struct sha256_block_state *state,
                                   const u8 *data, size_t nblocks)
{
    static u32 W[64];
    do {
        sha256_block_generic(state, data, W);
        data += SHA256_BLOCK_SIZE;
    } while (--nblocks);
}
/* Provide a BPF map to hold sha256_ctx + digest + 64-byte padding.
 * The padding is required because __sha256_final's memset loop accesses
 * ctx->buf[0..63] (offset 40..103) with a variable index that the verifier
 * conservatively bounds as umax=64.  Without padding the verifier computes
 * a worst-case offset of 40+64+64=168 > map_value_size=136 and rejects the
 * program.  Adding 64 bytes of padding raises the map value to 200 bytes,
 * making the worst-case access (off=136) safely within bounds. */
struct __bpf_sha256_data {
    struct sha256_ctx ctx;   /* 104 bytes: state(32)+bytecount(8)+buf[64] */
    u8 digest[32];           /* SHA256_DIGEST_SIZE */
    u8 pad[64];              /* verifier worst-case padding */
};
struct {
    __uint(type, 1 /* BPF_MAP_TYPE_ARRAY */);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct __bpf_sha256_data);
} __bpf_sha256_map __attribute__((section(".maps"), used));
