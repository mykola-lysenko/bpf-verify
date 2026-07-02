    /* __muldi3: assert multiply-by-zero and multiply-by-one identities.
     *
     * Commutativity (__muldi3(a,b) == __muldi3(b,a)) is NOT asserted.
     * The BPF verifier makes two independent function calls and tracks
     * their results as independent scalars; it cannot prove they are
     * equal without symbolic algebraic reasoning. This is a VERIFIER
     * PRECISION LIMITATION, not a bug in __muldi3.
     *
     * The zero and identity properties ARE provable: the verifier inlines
     * __muldi3 and can constant-fold the multiplication when one operand
     * is a known constant (0 or 1). */
    __u32 key0 = 0;
    __u64 *va = bpf_map_lookup_elem(&input_map, &key0);
    if (!va) return 0;
    /* Limit to 20-bit inputs to keep verifier state bounded */
    long long a = (long long)(*va & 0xfffff);
    /* Property: multiply by 0 gives 0 */
    long long r0 = __muldi3(a, 0LL);
    BPF_ASSERT(r0 == 0);
    /* Property: multiply by 1 gives identity */
    long long r1 = __muldi3(a, 1LL);
    BPF_ASSERT(r1 == a);
    return (int)(r1 >> 16);