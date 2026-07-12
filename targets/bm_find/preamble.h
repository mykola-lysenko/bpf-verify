/* Two distinct callbacks + a runtime-selected assignment force a genuinely
 * indirect call in bm_find (see harness.c). Config area is a static global:
 * struct ts_bm alone (bad_shift[256]) exceeds the 512-byte BPF stack. */
static unsigned int __bpf_next_block_a(unsigned int consumed, const u8 **dst,
        struct ts_config *conf, struct ts_state *st)
{
    (void)consumed; (void)conf; (void)st;
    *dst = (const u8 *)0;
    return 0; /* text_len == 0 -> bm_find terminates */
}
static unsigned int __bpf_next_block_b(unsigned int consumed, const u8 **dst,
        struct ts_config *conf, struct ts_state *st)
{
    (void)consumed; (void)conf; (void)st;
    *dst = (const u8 *)0;
    return 0;
}
static struct {
    struct ts_config conf;
    struct ts_bm bm;
    unsigned int good_shift_pad[8];
    u8 pat[8];
} __bpf_bm_area;
