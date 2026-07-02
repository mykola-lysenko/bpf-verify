/* lzo1x_1_do_compress (8 args, static noinline) and lzogeneric1x_1_compress
 * (6 args, static) need first declarations with internal_linkage so they use
 * BPF's static-subprogram stack-argument path. The shim pre-include (in
 * EXTRA_INCLUDES) ensures kernel headers are processed before #define static
 * takes effect.
 *
 * Actual signatures from lzo1x_compress.c:
 *   static noinline int lzo1x_1_do_compress(const unsigned char *in,
 *     size_t in_len, unsigned char **out, unsigned char *op_end, size_t *tp,
 *     void *wrkmem, signed char *state_offset,
 *     const unsigned char bitstream_version);
 *   static int lzogeneric1x_1_compress(const unsigned char *in,
 *     size_t in_len, unsigned char *out, size_t *out_len,
 *     void *wrkmem, const unsigned char bitstream_version);
 */
#define static
/* Rename the two exported functions so the BPF backend emits them as __bpf_*
 * symbols (not the external lzo1x_1_compress / lzorle1x_1_compress names).
 * Since they're never called from bpf_prog_lzo_compress, the BPF backend
 * will DCE them. We cannot add internal_linkage to them because their first
 * declaration in linux/lzo.h does not have that attribute. */
#define lzo1x_1_compress __bpf_lzo1x_1_compress
#define lzorle1x_1_compress __bpf_lzorle1x_1_compress
/* Apply internal_linkage to the two static helpers
 * (lzo1x_1_do_compress and lzogeneric1x_1_compress) which have >5 args.
 * Their first declaration is the forward decl below (no prior decl in lzo.h),
 * so internal_linkage is valid here. */
#pragma clang attribute push(__attribute__((internal_linkage)), apply_to=function)
__attribute__((internal_linkage))
int lzo1x_1_do_compress(
    const unsigned char *in, size_t in_len,
    unsigned char **out, unsigned char *op_end,
    size_t *tp, void *wrkmem,
    signed char *state_offset,
    const unsigned char bitstream_version);
__attribute__((internal_linkage))
int lzogeneric1x_1_compress(
    const unsigned char *in, size_t in_len,
    unsigned char *out, size_t *out_len,
    void *wrkmem, const unsigned char bitstream_version);
