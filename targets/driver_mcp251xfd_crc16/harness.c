    /* drivers/net/can/spi/mcp251xfd-crc16.c: standalone CAN controller CRC. */
    u8 data[8];
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0x1020304050607080ULL;
    u16 all;
    u16 split;
    int errors = 0;
    int i;

    for (i = 0; i < 8; i++)
        data[i] = (u8)(seed >> ((i & 7) * 8));

    all = mcp251xfd_crc16_compute(data, sizeof(data));
    split = mcp251xfd_crc16_compute2(data, 3, data + 3, sizeof(data) - 3);

    errors |= mcp251xfd_crc16_compute(data, 0) != 0xffff;
    errors |= all != split;

    return errors + all;