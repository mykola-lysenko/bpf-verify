    /* bcd: map-seeded BCD round-trip. Keep input in 0..99 so _bin2bcd()
     * stays within the two-digit BCD domain. */
    __u32 key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &key);
    unsigned val = input ? (unsigned)(*input % 100) : 42;
    unsigned char bcd = _bin2bcd(val);
    unsigned bin = _bcd2bin(bcd);
    return (int)(bin + bcd);