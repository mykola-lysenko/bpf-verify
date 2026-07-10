    /* clz_ctz provides __ctzsi2, __clzsi2, __ctzdi2, __clzdi2 */
    unsigned int x = 0xdeadbeef;
    int ctz = __ctzsi2(x);
    int clz = __clzsi2(x);
    return ctz + clz;
