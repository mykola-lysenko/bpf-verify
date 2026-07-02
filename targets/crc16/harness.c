    /* crc16 streaming/composition property.
     *
     * Execution contract (see targets/README.md): return 0 on success; the
     * only non-zero return is a BPF_ASSERT failure. CRC-16 is defined so that
     * processing a buffer in one call equals processing it in consecutive
     * chunks that thread the running CRC. A table or seed-handling bug breaks
     * this identity. Map-seeded bytes keep the computation live and fuzzed. */
    __u32 key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &key);
    u64 seed = input ? *input : 0x0102030405060708ULL;
    unsigned char buf[4];
    buf[0] = (unsigned char)seed;
    buf[1] = (unsigned char)(seed >> 8);
    buf[2] = (unsigned char)(seed >> 16);
    buf[3] = (unsigned char)(seed >> 24);
    u16 init = (u16)(seed >> 32);

    u16 whole = crc16(init, buf, 4);
    /* Same bytes, split 1 + 3 / 2 + 2 / 3 + 1, threading the running CRC. */
    u16 split13 = crc16(crc16(init, buf, 1), buf + 1, 3);
    u16 split22 = crc16(crc16(init, buf, 2), buf + 2, 2);
    u16 split31 = crc16(crc16(init, buf, 3), buf + 3, 1);
    BPF_ASSERT(split13 == whole);
    BPF_ASSERT(split22 == whole);
    BPF_ASSERT(split31 == whole);
    /* Empty chunk is a no-op. */
    BPF_ASSERT(crc16(whole, buf, 0) == whole);