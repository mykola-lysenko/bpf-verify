    /* tnum proof harness: verifier-enforced algebraic invariants over
     * dynamic map inputs. Unlike the smoke tnum target, these checks use
     * BPF_PROVE so a failed or unprovable invariant rejects the program.
     */
    __u32 key0 = 0, key1 = 1;
    __u64 *va = bpf_map_lookup_elem(&input_map, &key0);
    __u64 *vb = bpf_map_lookup_elem(&input_map, &key1);
    if (!va || !vb) return 0;
    u64 a = *va, b = *vb;

    struct tnum ca, cb, czero, unknown;
    struct tnum sum, diff, zero_and, ident_or, self_xor;
    struct tnum lshift, rshift, inter, uni;

    tnum_const_to_ptr(a, &ca);
    tnum_const_to_ptr(b, &cb);
    tnum_const_to_ptr(0, &czero);

    BPF_PROVE(ca.mask == 0 && ca.value == a);
    BPF_PROVE(cb.mask == 0 && cb.value == b);

    tnum_add_to_ptr(ca, cb, &sum);
    BPF_PROVE(sum.mask == 0 && sum.value == a + b);

    tnum_sub_to_ptr(ca, cb, &diff);
    BPF_PROVE(diff.mask == 0 && diff.value == a - b);

    tnum_and_to_ptr(ca, czero, &zero_and);
    BPF_PROVE(zero_and.mask == 0 && zero_and.value == 0);

    tnum_or_to_ptr(ca, czero, &ident_or);
    BPF_PROVE(ident_or.mask == 0 && ident_or.value == a);

    tnum_xor_to_ptr(ca, ca, &self_xor);
    BPF_PROVE(self_xor.mask == 0 && self_xor.value == 0);

    tnum_lshift_to_ptr(ca, 1, &lshift);
    BPF_PROVE(lshift.mask == 0 && lshift.value == (a << 1));

    tnum_rshift_to_ptr(ca, 1, &rshift);
    BPF_PROVE(rshift.mask == 0 && rshift.value == (a >> 1));

    unknown.value = 0;
    unknown.mask = (u64)-1;
    BPF_PROVE(tnum_in_wrap(unknown, ca));

    tnum_intersect_to_ptr(unknown, ca, &inter);
    BPF_PROVE(inter.mask == 0 && inter.value == a);

    tnum_union_to_ptr(ca, cb, &uni);
    BPF_PROVE(tnum_in_wrap(uni, ca));
    BPF_PROVE(tnum_in_wrap(uni, cb));

    return (int)(sum.value ^ diff.value ^ lshift.value ^ rshift.value);
