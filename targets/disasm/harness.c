    /* disasm: func_id_name() bounds-checks the helper id, but the check lands
     * on a different register than the array index it already computed, so for
     * a *symbolic* id the verifier cannot propagate the bound and rejects the
     * .rodata access -- a verifier-precision limitation in real kernel code.
     * Verified as a compile/load check only. */
    return 0;
