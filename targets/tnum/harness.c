    /* tnum (tristate number) -- the BPF verifier's own abstract domain.
     *
     * tnum tracks which bits of a value are known (0 or 1) vs unknown (x).
     * Every tnum is represented as (value, mask): a bit is known-0 if both
     * value and mask are 0, known-1 if value=1 and mask=0, and unknown if
     * mask=1 (value bit is irrelevant).
     *
     * We verify key algebraic properties of the tnum lattice operations:
     *   1. tnum_const(c) is a known constant: mask == 0, value == c.
     *   2. tnum_add(tnum_const(a), tnum_const(b)) == tnum_const(a+b).
     *   3. tnum_and(x, tnum_const(0)) == tnum_const(0) for any x.
     *   4. tnum_or(x, tnum_const(0)) == x (identity for OR).
     *   5. tnum_in(tnum_unknown, any_const) is always true.
     *
     * Note: tnum functions return struct by value (StructRet), which the BPF
     * backend does not support for non-inlined functions. We use pointer-based
     * wrappers (defined in EXTRA_PREAMBLE) that call the internal_linkage
     * versions and write the result through a pointer.
     */
    __u32 key0 = 0, key1 = 1;
    __u64 *va = bpf_map_lookup_elem(&input_map, &key0);
    __u64 *vb = bpf_map_lookup_elem(&input_map, &key1);
    if (!va || !vb) return 0;
    u64 a = *va, b = *vb;

    /* Property 1: tnum_const produces a known constant (mask == 0). */
    struct tnum ca, cb, sum, zero_and, ident_or, czero;
    tnum_const_to_ptr(a, &ca);
    tnum_const_to_ptr(b, &cb);
    tnum_const_to_ptr(0, &czero);
    BPF_ASSERT(ca.mask == 0 && ca.value == a);
    BPF_ASSERT(cb.mask == 0 && cb.value == b);

    /* Property 2: const + const = const(a+b). */
    tnum_add_to_ptr(ca, cb, &sum);
    BPF_ASSERT(sum.mask == 0);
    BPF_ASSERT(sum.value == a + b);

    /* Property 3: x & const(0) == const(0). */
    tnum_and_to_ptr(ca, czero, &zero_and);
    BPF_ASSERT(zero_and.mask == 0 && zero_and.value == 0);

    /* Property 4: x | const(0) == x (identity). */
    tnum_or_to_ptr(ca, czero, &ident_or);
    BPF_ASSERT(ident_or.mask == 0 && ident_or.value == a);

    /* Property 5: tnum_in(tnum_unknown, any_const) is always true. */
    struct tnum unk = { .value = 0, .mask = (u64)-1 };
    BPF_ASSERT(tnum_in_wrap(unk, ca));

    return (int)(sum.value & 0xff);