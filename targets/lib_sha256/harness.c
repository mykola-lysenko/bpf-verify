    /* Use a BPF map (defined in EXTRA_PREAMBLE) to hold sha256_ctx.
     * The EXTRA_PREAMBLE provides a sha256_blocks_generic wrapper that uses
     * a static W[64] array instead of a stack-allocated one, reducing the
     * BPF stack depth from 496 to ~240 bytes (rounds up to 256).
     * Combined call-chain depth: harness(32) + sha256_blocks_generic(256) = 288 bytes. */
    static const u8 __bpf_data[64] = {0};
    __u32 __key = 0;
    struct __bpf_sha256_data *__d = bpf_map_lookup_elem(&__bpf_sha256_map, &__key);
    if (!__d) return 0;
    sha256_init(&__d->ctx);
    sha256_blocks_generic(&__d->ctx.ctx.state, __bpf_data, 1);
    return (int)__d->ctx.ctx.state.h[0];
