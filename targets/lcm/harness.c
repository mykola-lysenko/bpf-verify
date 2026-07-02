    /* lcm: compile-only test -- lcm() calls gcd() internally, which uses
     * an unbounded for(;;) loop. The BPF verifier rejects the back-edge
     * in gcd's loop even when lcm is called with constant inputs, because
     * LLVM's BPF backend does not constant-fold the loop body away.
     *
     * C-related finding: lib/math/lcm.c calls gcd() which uses an unbounded
     * for(;;) loop (binary GCD algorithm). The BPF verifier reports
     * "back-edge" because it cannot prove loop termination. This is an
     * indirect incompatibility: lcm.c itself is simple, but its dependency
     * on gcd.c's unbounded loop makes the combined code unverifiable. */
    return 0;