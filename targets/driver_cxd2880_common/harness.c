    /* drivers/media/dvb-frontends/cxd2880_common.c: signed complement conversion. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u32 value = input ? (u32)*input : 0x80;
    u32 bitlen = input ? (u32)((*input >> 32) & 31) : 8;
    int errors = 0;

    errors |= cxd2880_convert2s_complement(0x7f, 8) != 127;
    errors |= cxd2880_convert2s_complement(0x80, 8) != -128;
    errors |= cxd2880_convert2s_complement(0xff, 8) != -1;
    errors |= cxd2880_convert2s_complement(0x7ff, 12) != 2047;
    errors |= cxd2880_convert2s_complement(0x800, 12) != -2048;

    return errors + cxd2880_convert2s_complement(value, bitlen);