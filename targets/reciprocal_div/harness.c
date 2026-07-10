    /* reciprocal_value returns a struct by value -- BPF does not support
     * StructRet ABI. We call it via a pointer-based wrapper defined in
     * the harness preamble (see EXTRA_PREAMBLE for reciprocal_div).
     * Use struct __bpf_recip_rv (the renamed tag) since the reciprocal_value
     * macro was undef'd after the source include. */
    struct __bpf_recip_rv rv;
    reciprocal_value_to_ptr(7, &rv);
    return (int)rv.m;
