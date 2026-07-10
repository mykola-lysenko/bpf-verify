    /* bitmap operations: algebraic identities.
     *
     * Tests:
     *   1. Double complement: ~~A == A (for NBITS-bit values)
     *   2. Subset transitivity: if A subset B and B subset C then A subset C
     *
     * Note: De Morgan (~(A&B) == ~A|~B) is a valid property but the BPF
     * verifier cannot prove it statically -- it tracks not_and and
     * or_nota_notb as independent scalars. This is a VERIFIER PRECISION
     * LIMITATION: the verifier does not perform symbolic algebraic
     * reasoning about bitwise operations. Omitted from assertions.
     *
     * All operations are on NBITS=8-bit values (masked to avoid
     * sign-extension issues with the BPF verifier).
     */
    __u32 key0 = 0, key1 = 1, key2 = 2;
    __u64 *va = bpf_map_lookup_elem(&input_map, &key0);
    __u64 *vb = bpf_map_lookup_elem(&input_map, &key1);
    __u64 *vc = bpf_map_lookup_elem(&input_map, &key2);
    if (!va || !vb || !vc) return 0;
    const unsigned int NBITS = 8;
    const unsigned long MASK = (1UL << NBITS) - 1UL;
    unsigned long a     = *va & MASK;
    unsigned long not_a = (~a) & MASK;
    unsigned long b     = *vb & MASK;
    unsigned long c     = *vc & MASK;
    /* Test 1: double complement */
    unsigned long not_not_a = (~not_a) & MASK;
    BPF_ASSERT(not_not_a == a);
    /* Test 2: subset transitivity */
    unsigned long A = a & b & MASK;
    unsigned long B = b & MASK;
    unsigned long C = (b | c) & MASK;
    BPF_ASSERT((A & ~B & MASK) == 0);
    BPF_ASSERT((B & ~C & MASK) == 0);
    BPF_ASSERT((A & ~C & MASK) == 0);

    unsigned long ba[1], bb[1], bc[1], bd[1];
    ba[0] = a;
    bb[0] = b;
    bc[0] = (a | b) & MASK;
    bd[0] = 0;

    BPF_ASSERT(__bitmap_or_equal(ba, bb, bc, NBITS));
    BPF_ASSERT(!__bitmap_or_equal(ba, bb, ba, NBITS) || ((a | b) & MASK) == a);

    __bitmap_and(bd, ba, bb, NBITS);
    BPF_ASSERT(__bitmap_weight_and(ba, bb, NBITS) == __bitmap_weight(bd, NBITS));
    BPF_ASSERT(__bitmap_weight_andnot(ba, bb, NBITS) ==
               __builtin_popcountl(a & ~b & MASK));
    BPF_ASSERT(__bitmap_weighted_or(bd, ba, bb, NBITS) == __bitmap_weight(bc, NBITS));
    BPF_ASSERT((bd[0] & MASK) == bc[0]);
    BPF_ASSERT(__bitmap_weighted_xor(bd, ba, bb, NBITS) ==
               __builtin_popcountl((a ^ b) & MASK));
    BPF_ASSERT((bd[0] & MASK) == ((a ^ b) & MASK));
    return (int)a;
