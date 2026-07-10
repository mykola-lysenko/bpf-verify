    /* drivers/net/phy/open_alliance_helpers.c: TDR status and distance decoding. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u16 reg = input ? (u16)*input : 0;
    int errors = 0;

    errors |= oa_1000bt1_get_ethtool_cable_result_code(
        OA_1000BT1_HDD_TDR_STATUS_CABLE_OK << 4) !=
        ETHTOOL_A_CABLE_RESULT_CODE_OK;
    errors |= oa_1000bt1_get_ethtool_cable_result_code(
        OA_1000BT1_HDD_TDR_STATUS_OPEN << 4) !=
        ETHTOOL_A_CABLE_RESULT_CODE_OPEN;
    errors |= oa_1000bt1_get_ethtool_cable_result_code(
        OA_1000BT1_HDD_TDR_STATUS_SHORT << 4) !=
        ETHTOOL_A_CABLE_RESULT_CODE_SAME_SHORT;
    errors |= oa_1000bt1_get_ethtool_cable_result_code(
        OA_1000BT1_HDD_TDR_STATUS_NOISE << 4) !=
        ETHTOOL_A_CABLE_RESULT_CODE_NOISE;
    errors |= oa_1000bt1_get_tdr_distance(
        OA_1000BT1_HDD_TDR_DISTANCE_RESOLUTION_NOT_POSSIBLE << 8) != -ERANGE;
    errors |= oa_1000bt1_get_tdr_distance(7 << 8) != 700;

    return errors + oa_1000bt1_get_ethtool_cable_result_code(reg) +
           oa_1000bt1_get_tdr_distance(reg);
