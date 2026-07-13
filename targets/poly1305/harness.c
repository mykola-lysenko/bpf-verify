    /* DOCUMENTED VERIFIER BOUNDARY (expect_failure target).
     *
     * poly1305 is the 130-bit one-time MAC in 26-bit limbs (WireGuard's
     * authenticator). Its STREAMING API keeps a partial-block byte count
     * (desc->buflen) as state, and poly1305_final writes a padding byte at
     * desc->buf[buflen] = 1. On a SEEDED (non-constant) message the verifier
     * cannot prove buflen == 0: poly1305_update ends with `nbytes %= 16`, whose
     * result the verifier tracks as the range [0,15] even for a compile-time
     * 32-byte message, so it explores final's partial-block branch with an
     * unbounded buflen -> "invalid unbounded variable-offset write to stack".
     * Inlining the whole call graph (-inline-threshold) does not help; only a
     * constant message folds buflen to a literal 0, which makes the target
     * born-trivial (constant-folded, covers nothing). So the streaming MAC is
     * boundary-bound for meaningful (seeded) coverage. If it ever verifies, the
     * verifier learned to bound modular streaming state -- promote it.
     *
     * (The AES-GCM path avoids this because its GHASH consumes whole 16-byte
     * blocks with no cross-call partial-buffer state.) */
    __u32 k0 = 0, k1 = 1, k2 = 2, k3 = 3;
    __u64 *a = bpf_map_lookup_elem(&input_map, &k0);
    __u64 *b = bpf_map_lookup_elem(&input_map, &k1);
    __u64 *c = bpf_map_lookup_elem(&input_map, &k2);
    __u64 *d = bpf_map_lookup_elem(&input_map, &k3);

    struct poly1305_desc_ctx pa;
    int i;
    #pragma clang loop unroll(disable)
    for (i = 0; i < 16; i++) {
        __bpf_poly.key[i]      = (u8)((a ? *a : 0x0123456789abcdefULL) >> ((i & 7) * 8));
        __bpf_poly.key[i + 16] = (u8)((b ? *b : 0xfedcba9876543210ULL) >> ((i & 7) * 8));
        __bpf_poly.msg[i]      = (u8)((c ? *c : 0x1122334455667788ULL) >> ((i & 7) * 8));
        __bpf_poly.msg[i + 16] = (u8)((d ? *d : 0x8877665544332211ULL) >> ((i & 7) * 8));
    }

    poly1305_init(&pa, __bpf_poly.key);
    poly1305_update(&pa, __bpf_poly.msg, 32);
    poly1305_final(&pa, __bpf_poly.tag1);

    return (int)__bpf_poly.tag1[0];
