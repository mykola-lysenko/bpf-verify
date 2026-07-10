    /* cnum: circular number range operations used by verifier range logic.
     *
     * Cover unsigned/signed projections, wraparound ranges, intersections,
     * mutation helpers, subset checks, and the 64-bit-to-32-bit tightening
     * helper that reasons across u32 wrap boundaries. */
    struct cnum32 a32 = cnum32_from_urange(10, 20);
    struct cnum32 b32 = cnum32_from_urange(15, 25);
    struct cnum32 i32 = cnum32_intersect(a32, b32);
    struct cnum32 empty32 = cnum32_intersect(cnum32_from_urange(10, 12),
                                             cnum32_from_urange(20, 22));
    struct cnum32 wrap32 = cnum32_from_urange(U32_MAX - 2, 1);
    struct cnum32 signed32 = cnum32_from_srange(-2, 3);
    struct cnum32 fulls32 = cnum32_from_srange(S32_MIN, S32_MAX);
    struct cnum32 sum32 = cnum32_add(cnum32_from_urange(1, 3),
                                     cnum32_from_urange(4, 6));
    struct cnum32 neg32 = cnum32_negate(cnum32_from_urange(1, 3));
    struct cnum32 mut32 = cnum32_from_urange(0, 100);
    struct cnum64 a64 = cnum64_from_urange(100, 200);
    struct cnum64 b64 = cnum64_from_srange(-5, 5);
    struct cnum64 i64;
    struct cnum64 empty64;
    struct cnum64 wrap_i64;
    struct cnum32 from64;
    struct cnum32 from64_wide;

    BPF_ASSERT(a32.base == 10 && a32.size == 10);
    BPF_ASSERT(cnum32_umin(a32) == 10 && cnum32_umax(a32) == 20);
    BPF_ASSERT(cnum32_contains(a32, 15));
    BPF_ASSERT(!cnum32_contains(a32, 21));
    BPF_ASSERT(i32.base == 15 && i32.size == 5);
    BPF_ASSERT(cnum32_is_empty(empty32));

    BPF_ASSERT(cnum32_umin(wrap32) == 0);
    BPF_ASSERT(cnum32_umax(wrap32) == U32_MAX);
    BPF_ASSERT(cnum32_contains(wrap32, U32_MAX));
    BPF_ASSERT(cnum32_contains(wrap32, 0));
    BPF_ASSERT(!cnum32_contains(wrap32, 2));

    BPF_ASSERT(cnum32_smin(signed32) == -2);
    BPF_ASSERT(cnum32_smax(signed32) == 3);
    BPF_ASSERT(cnum32_smin(fulls32) == S32_MIN);
    BPF_ASSERT(cnum32_smax(fulls32) == S32_MAX);

    BPF_ASSERT(sum32.base == 5 && sum32.size == 4);
    BPF_ASSERT(cnum32_smin(neg32) == -3);
    BPF_ASSERT(cnum32_smax(neg32) == -1);
    BPF_ASSERT(cnum32_is_subset(a32, cnum32_from_urange(12, 15)));
    BPF_ASSERT(!cnum32_is_subset(cnum32_from_urange(12, 15), a32));

    cnum32_intersect_with_urange(&mut32, 25, 30);
    BPF_ASSERT(mut32.base == 25 && mut32.size == 5);
    cnum32_intersect_with_srange(&mut32, 26, 27);
    BPF_ASSERT(mut32.base == 26 && mut32.size == 1);

    BPF_ASSERT(cnum64_umin(a64) == 100 && cnum64_umax(a64) == 200);
    BPF_ASSERT(cnum64_smin(b64) == -5 && cnum64_smax(b64) == 5);
    BPF_ASSERT(cnum64_contains(b64, (u64)-1));
    BPF_ASSERT(!cnum64_contains(b64, 6));

    i64 = cnum64_cnum32_intersect(cnum64_from_urange(0x100000000ULL + 10,
                                                     0x100000000ULL + 30),
                                  cnum32_from_urange(15, 20));
    BPF_ASSERT(i64.base == 0x100000000ULL + 15 && i64.size == 5);

    empty64 = cnum64_cnum32_intersect(cnum64_from_urange(10, 12),
                                      cnum32_from_urange(20, 25));
    BPF_ASSERT(cnum64_is_empty(empty64));

    wrap_i64 = cnum64_cnum32_intersect(cnum64_from_urange(0x100000000ULL,
                                                          0x100000000ULL + 4),
                                       cnum32_from_urange(U32_MAX - 2, 2));
    BPF_ASSERT(wrap_i64.base == 0x100000000ULL && wrap_i64.size == 2);

    from64 = cnum32_from_cnum64(cnum64_from_urange(0x100000005ULL,
                                                   0x10000000aULL));
    BPF_ASSERT(from64.base == 5 && from64.size == 5);
    from64_wide = cnum32_from_cnum64((struct cnum64){ .base = 123,
                                                      .size = U32_MAX });
    BPF_ASSERT(from64_wide.base == 0 && from64_wide.size == U32_MAX);

    return (int)(i32.base + mut32.base + from64.base);
