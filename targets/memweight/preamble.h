unsigned int __bitmap_weight(const unsigned long *src, unsigned int nbits)
{
    unsigned int w = 0;
    unsigned int len = (nbits + BITS_PER_LONG - 1) / BITS_PER_LONG;
    unsigned int i;
    for (i = 0; i < len; i++)
        w += __builtin_popcountl(src[i]);
    return w;
}
