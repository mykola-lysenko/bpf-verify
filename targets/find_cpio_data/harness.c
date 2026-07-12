    /* DOCUMENTED VERIFIER BOUNDARY (expect_failure target).
     *
     * find_cpio_data() aligns its record cursors with PTR_ALIGN(p + off, 4),
     * which compiles to a bitwise AND on a stack pointer. The BPF verifier
     * prohibits bitwise ops on pointers, so the program is REJECTED at that
     * site with "bitwise operator &= on pointer prohibited" -- a real boundary
     * in unmodified kernel source, pinned here as a regression-guarded
     * characterization. If this target ever verifies, the boundary was lifted
     * (see check_results.py).
     *
     * The harness stages a well-formed "newc" (070701) cpio header so the parse
     * loop, hex-field decode and bounds checks all run up to the PTR_ALIGN. */
    __u32 k0 = 0;
    __u64 *lp = bpf_map_lookup_elem(&input_map, &k0);
    __u64 lv = lp ? *lp : 0;

    unsigned char buf[128];
    /* Fill with ASCII '0' so every hex field decodes to a valid value. */
    #pragma clang loop unroll(disable)
    for (int i = 0; i < (int)sizeof(buf); i++)
        buf[i] = '0';
    /* newc magic in the first 6 bytes. */
    buf[0]='0'; buf[1]='7'; buf[2]='0'; buf[3]='7'; buf[4]='0'; buf[5]='1';

    /* Bound the length to the buffer so the parser cannot walk past it, while
     * keeping it map-derived (non-constant) for the bounds check. */
    __u64 len = 64 + (lv & 63);
    if (len > sizeof(buf))
        len = sizeof(buf);

    char path[2]; path[0] = 'x'; path[1] = 0;
    long offset = 0;
    struct cpio_data cd = find_cpio_data(path, buf, (size_t)len, &offset);

    return (int)cd.size;
