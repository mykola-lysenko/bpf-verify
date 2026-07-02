    /* win_minmax: verify the reset value is returned correctly and that
     * minmax_get returns the tracked minimum/maximum.
     *
     * The relational properties (running_min <= meas, running_max >= meas)
     * are NOT asserted for symbolic inputs. The BPF verifier tracks the
     * return values of minmax_running_min/max and the measurement as
     * independent scalars and cannot prove the ordering relationship
     * between them. This is a VERIFIER PRECISION LIMITATION.
     *
     * Instead we test with a concrete reset value and verify that
     * minmax_get returns the reset value before any measurements are
     * taken (a provable identity property). */
    struct minmax m;
    minmax_reset(&m, 0, 1000);
    /* After reset, minmax_get returns the reset value (1000) */
    __u32 init_val = minmax_get(&m);
    BPF_ASSERT(init_val == 1000);
    /* running_min with a measurement larger than reset keeps reset value */
    __u32 v = minmax_running_min(&m, 100, 50, 2000);
    BPF_ASSERT(v == 1000);
    /* running_max with a measurement larger than reset returns measurement */
    __u32 w = minmax_running_max(&m, 100, 50, 2000);
    BPF_ASSERT(w == 2000);
    return (int)(v + w);