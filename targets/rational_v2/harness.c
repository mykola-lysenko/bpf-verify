    /* rational_best_approximation: the continued-fraction loop does not verify
     * with symbolic inputs (termination is arithmetic, not syntactically
     * bounded), so this is a compile/load check only. The algorithm's bounds
     * property is fuzzed in userspace instead (FINDINGS_EXECUTION.md: 50M
     * inputs, no overshoot). */
    return 0;
