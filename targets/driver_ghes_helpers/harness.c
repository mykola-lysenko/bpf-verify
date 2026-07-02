    /* drivers/acpi/apei/ghes_helpers.c: CXL CPER protocol-error validation. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0x1122334455667788ULL;
    struct __bpf_ghes_prot_err_record raw = {};
    struct __bpf_ghes_state *state;
    struct cxl_cper_prot_err_work_data *wd;
    u64 saved_valid;
    u16 saved_err_len;
    int errors = 0;

    state = bpf_map_lookup_elem(&__bpf_ghes_state_map, &input_key);
    if (!state)
        return 0;

    wd = &state->wd;

    raw.err.valid_bits = PROT_ERR_VALID_AGENT_ADDRESS |
                         PROT_ERR_VALID_ERROR_LOG |
                         PROT_ERR_VALID_SERIAL_NUMBER;
    raw.err.agent_type = (seed & 1) ? DEVICE : RP;
    raw.err.dvsec_len = sizeof(raw.dvsec);
    raw.err.err_len = sizeof(struct cxl_ras_capability_regs);
    raw.ras.uncor_status = (u32)seed;
    raw.ras.cor_status = (u32)(seed >> 32);
    saved_valid = raw.err.valid_bits;
    saved_err_len = raw.err.err_len;

    raw.err.valid_bits = saved_valid & ~PROT_ERR_VALID_AGENT_ADDRESS;
    errors |= cxl_cper_sec_prot_err_valid(&raw.err) != -EINVAL;

    raw.err.valid_bits = saved_valid & ~PROT_ERR_VALID_ERROR_LOG;
    errors |= cxl_cper_sec_prot_err_valid(&raw.err) != -EINVAL;

    raw.err.valid_bits = saved_valid;
    raw.err.err_len = 1;
    errors |= cxl_cper_sec_prot_err_valid(&raw.err) != -EINVAL;

    raw.err.err_len = saved_err_len;
    errors |= cxl_cper_sec_prot_err_valid(&raw.err) != 0;
    errors |= cxl_cper_setup_prot_err_work_data(wd, &raw.err,
                                                (int)(seed & 3)) != 0;
    errors |= wd->prot_err.err_len != sizeof(struct cxl_ras_capability_regs);
    errors |= wd->ras_cap.uncor_status != raw.ras.uncor_status;

    raw.err.agent_type = 0xff;
    errors |= cxl_cper_setup_prot_err_work_data(wd, &raw.err, 1) != -EINVAL;

    return errors + wd->severity + wd->ras_cap.cor_status;