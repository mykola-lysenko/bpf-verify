    /* cordic_calc_iq computes i/q coordinate for a given angle.
     * cordic_calc_iq() returns struct by value (StructRet) which BPF does not
     * support. We use the pointer-based wrapper cordic_calc_iq_to_ptr() instead.
     * The wrapper is defined in EXTRA_PREAMBLE after the source include. */
    struct __bpf_cordic_iq result;
    cordic_calc_iq_to_ptr(45, &result);
    return (int)(result.i + result.q);
