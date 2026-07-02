
    /* arc4: just verify the functions compile and link.
     * arc4_ctx has a 1024-byte S-box (u32 S[256]) that exceeds BPF's
     * 512-byte stack limit, so we can't instantiate it on the stack. */
    (void)arc4_setkey;
    (void)arc4_crypt;
    return 0;
