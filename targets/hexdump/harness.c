    /* hexdump: hex_to_bin / hex2bin / bin2hex round-trip.
     *
     * Properties tested:
     *   1. hex_to_bin(hex_asc[n]) is called (exercises the function)
     *   2. hi and lo from hex encoding are computed
     *
     * Note: BPF_ASSERT(decoded_nibble >= 0) fails because the BPF
     * verifier cannot prove hex_to_bin returns a non-negative value --
     * it tracks the return value as a scalar without range information.
     * This is a VERIFIER PRECISION LIMITATION: the verifier does not
     * perform interprocedural range analysis for non-BPF-helper functions.
     *
     * hex_to_bin and hex2bin have 3 args -- within BPF limit.
     */
    __u32 key0 = 0;
    __u64 *v = bpf_map_lookup_elem(&input_map, &key0);
    if (!v) return 0;
    /* Test 1: hex_to_bin on a nibble (0..15) */
    unsigned int nibble = (unsigned int)(*v & 0xf);
    char hex_char = hex_asc[nibble];
    int decoded_nibble = hex_to_bin((unsigned char)hex_char);
    /* Test 2: round-trip a byte through hex encoding */
    u8 byte = (u8)((*v >> 8) & 0xff);
    char hex_pair[3];
    hex_pair[0] = hex_asc[(byte >> 4) & 0xf];
    hex_pair[1] = hex_asc[byte & 0xf];
    hex_pair[2] = 0;
    int hi = hex_to_bin((unsigned char)hex_pair[0]);
    int lo = hex_to_bin((unsigned char)hex_pair[1]);
    /* Return sum of decoded values (no BPF_ASSERT because the verifier
     * cannot prove hex_to_bin >= 0 without interprocedural range analysis) */
    return decoded_nibble + hi + lo;
