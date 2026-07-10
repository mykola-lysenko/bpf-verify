    /* polynomial_calc: integer polynomial evaluation.
     *
     * Properties tested:
     *   1. Zero polynomial (all coef=0) returns 0 for any input
     *   2. Identity polynomial f(x)=x returns x
     *   3. Constant polynomial f(x)=k returns k
     *
     * polynomial_calc takes 2 args -- within BPF limit.
     * We define polynomials as compound literals on the stack.
     */
    __u32 key0 = 0;
    __u64 *vx = bpf_map_lookup_elem(&input_map, &key0);
    if (!vx) return 0;
    long x = (long)((s32)(*vx & 0xffff));  /* 16-bit signed input */
    volatile long vx2 = x;
    x = vx2;

    /* Property 1: zero polynomial -- single term deg=0, coef=0 */
    struct { long total_divider; struct polynomial_term terms[1]; } zero_poly = {
        .total_divider = 1,
        .terms = {{ .deg = 0, .coef = 0, .divider = 1, .divider_leftover = 1 }},
    };
    long r0 = polynomial_calc((const struct polynomial *)&zero_poly, x);
    BPF_ASSERT(r0 == 0);

    /* Property 2: identity polynomial f(x) = x  (deg=1, coef=1, div=1) */
    struct { long total_divider; struct polynomial_term terms[2]; } id_poly = {
        .total_divider = 1,
        .terms = {
            { .deg = 1, .coef = 1, .divider = 1, .divider_leftover = 1 },
            { .deg = 0, .coef = 0, .divider = 1, .divider_leftover = 1 },
        },
    };
    long r1 = polynomial_calc((const struct polynomial *)&id_poly, x);
    BPF_ASSERT(r1 == x);

    /* Property 3: constant polynomial f(x) = 42 */
    struct { long total_divider; struct polynomial_term terms[1]; } const_poly = {
        .total_divider = 1,
        .terms = {{ .deg = 0, .coef = 42, .divider = 1, .divider_leftover = 1 }},
    };
    long r2 = polynomial_calc((const struct polynomial *)&const_poly, x);
    BPF_ASSERT(r2 == 42);
    return (int)(r0 + r1 + r2);
