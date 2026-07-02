    /* hexdump: hex_to_bin round-trip properties.
     *
     * Execution contract (see targets/README.md): return 0 on success; the
     * only non-zero return is a BPF_ASSERT failure. These are exactly the
     * properties the load-only harness could NOT assert because the verifier
     * lacks interprocedural range analysis for hex_to_bin's return value --
     * the execution leg checks them on real inputs instead. */
    __u32 key0 = 0;
    __u64 *v = bpf_map_lookup_elem(&input_map, &key0);
    if (!v) return 0;

    /* Property 1: hex_to_bin inverts the hex_asc table for every nibble. */
    unsigned int nibble = (unsigned int)(*v & 0xf);
    int decoded_nibble = hex_to_bin((unsigned char)hex_asc[nibble]);
    BPF_ASSERT(decoded_nibble == (int)nibble);

    /* Property 2: encode a byte to two hex chars and decode back == byte. */
    u8 byte = (u8)((*v >> 8) & 0xff);
    int hi = hex_to_bin((unsigned char)hex_asc[(byte >> 4) & 0xf]);
    int lo = hex_to_bin((unsigned char)hex_asc[byte & 0xf]);
    BPF_ASSERT(hi >= 0 && lo >= 0);
    BPF_ASSERT((((unsigned)hi << 4) | (unsigned)lo) == byte);

    /* Property 3: hex_to_bin rejects non-hex input with a negative return.
     * Pick a byte guaranteed to be outside [0-9a-fA-F]. */
    unsigned char non_hex = (unsigned char)('g' + (*v & 0x7)); /* 'g'..'n' */
    BPF_ASSERT(hex_to_bin(non_hex) < 0);