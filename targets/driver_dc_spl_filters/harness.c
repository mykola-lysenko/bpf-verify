    /* drivers/gpu/drm/amd/display/dc/sspl/dc_spl_filters.c: S1.10 -> S1.12 conversion. */
    uint16_t in[NUM_PHASES_COEFF * 2];
    uint16_t out[NUM_PHASES_COEFF * 2];
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0x0102030405060708ULL;
    int errors = 0;
    int i;

    for (i = 0; i < NUM_PHASES_COEFF * 2; i++)
        in[i] = (uint16_t)((seed >> ((i & 7) * 8)) + i);

    convert_filter_s1_10_to_s1_12(in, out, 2);

    for (i = 0; i < NUM_PHASES_COEFF * 2; i++)
        errors |= out[i] != (uint16_t)(in[i] * 4);

    return errors + out[0];