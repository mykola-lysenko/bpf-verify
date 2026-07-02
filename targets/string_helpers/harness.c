
    /* string_helpers: test string_unescape with UNESCAPE_SPACE | UNESCAPE_OCTAL */
    /* Keep the source buffer fully initialized. The verifier explores
     * impossible escape paths when bytes are not tracked as constants, so
     * padding avoids speculative uninitialized stack reads. */
    char src[64] = {0};
    char dst[32] = {0};
    src[0] = 'h';
    src[1] = 'e';
    src[2] = 'l';
    src[3] = 'l';
    src[4] = 'o';
    int n = string_unescape(src, dst, sizeof(dst),
                            UNESCAPE_SPACE | UNESCAPE_OCTAL);
    /* n is the number of bytes written (always >= 0) */
    (void)n;
    return 0;
