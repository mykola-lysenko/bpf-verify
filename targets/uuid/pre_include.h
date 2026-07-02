/* Stub get_random_bytes and hex_to_bin to avoid extern BTF references. */
static inline void get_random_bytes(void *buf, int nbytes)
    { (void)buf; (void)nbytes; }
static inline int hex_to_bin(unsigned char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}
