    /* base64_encode / base64_decode round-trip identity.
     *
     * Execution contract (see targets/README.md): return 0 on success; the
     * only non-zero return is a BPF_ASSERT failure. Encode 3 map-seeded bytes
     * to 4 base64 chars and decode back; the decoded bytes must equal the
     * source. This is a genuine oracle the verifier cannot check statically
     * (it loses the decoded pointer's bounds), but the execution leg can. */
    __u32 key0 = 0;
    __u64 *v = bpf_map_lookup_elem(&input_map, &key0);
    if (!v) return 0;
    /* 3 source bytes packed into the low 24 bits */
    u8 src[3];
    src[0] = (u8)((*v >>  0) & 0xff);
    src[1] = (u8)((*v >>  8) & 0xff);
    src[2] = (u8)((*v >> 16) & 0xff);
    /* Encode: 3 bytes -> 4 base64 chars. 64-byte buffer keeps the verifier's
     * loop-bound analysis inside base64_decode happy. */
    char enc[64];
    base64_encode(src, 3, enc, false, BASE64_STD);
    u8 dec[48];
    int dlen = base64_decode(enc, 4, dec, false, BASE64_STD);
    /* Property: 3 bytes encode to 4 chars and decode back to exactly 3. */
    BPF_ASSERT(dlen == 3);
    /* Property: the round-trip is the identity on the source bytes. */
    BPF_ASSERT(dec[0] == src[0]);
    BPF_ASSERT(dec[1] == src[1]);
    BPF_ASSERT(dec[2] == src[2]);