    /* crc8: use map input for the data bytes so verifier cannot
     * constant-fold the CRC computation. This forces full exploration
     * of the CRC loop body across all 256 table entries. */
    __u32 key = 0;
    __u64 *vdata = bpf_map_lookup_elem(&input_map, &key);
    if (!vdata) return 0;
    __u8 table[256];
    /* The 4 data bytes come from the map value (unknown to verifier) */
    __u8 b0 = (__u8)((*vdata) >>  0);
    __u8 b1 = (__u8)((*vdata) >>  8);
    __u8 b2 = (__u8)((*vdata) >> 16);
    __u8 b3 = (__u8)((*vdata) >> 24);
    __u8 buf[4] = {{b0, b1, b2, b3}};
    crc8_populate_msb(table, 0x07);
    __u8 crc = crc8(table, buf, sizeof(buf), 0);
    return (int)crc;