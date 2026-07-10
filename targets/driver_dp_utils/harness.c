    /* drivers/gpu/drm/msm/dp/dp_utils.c: DisplayPort SDP parity/header packing. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0x1020304050607080ULL;
    struct dp_sdp_header header = {
        .HB0 = (u8)seed,
        .HB1 = (u8)(seed >> 8),
        .HB2 = (u8)(seed >> 16),
        .HB3 = (u8)(seed >> 24),
    };
    u32 packed[2] = {};
    u8 data = (u8)(seed >> 32);
    u8 g0 = msm_dp_utils_get_g0_value(data);
    u8 g1 = msm_dp_utils_get_g1_value(data);
    u8 parity = msm_dp_utils_calculate_parity((u32)seed);

    msm_dp_utils_pack_sdp_header(&header, packed);

    return (int)(g0 + g1 + parity + packed[0] + packed[1]);
