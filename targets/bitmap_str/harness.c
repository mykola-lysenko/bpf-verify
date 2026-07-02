
    /* bitmap_str: test bitmap_parselist and bitmap_weight */
    DECLARE_BITMAP(bmap, 64);
    bitmap_zero(bmap, 64);
    /* parselist "0-3,8" should set bits 0,1,2,3,8 => weight 5 */
    int ret = bitmap_parselist("0-3,8", bmap, 64);
    if (ret != 0) { *(volatile int *)0 = 0; }
    int w = bitmap_weight(bmap, 64);
    if (w != 5) { *(volatile int *)0 = 0; }
    return 0;
