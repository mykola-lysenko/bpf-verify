/* Same setup as targets/lib_aes: the kernel rotate helpers are static inline
 * but can be left as unresolved externs under the BPF/gnu89 inline model.
 * Include their definitions first, then force AES call sites to use expression
 * macros. aes.c itself is included here (after the macros, before aescfb.c) so
 * aes_prepareenckey/aes_encrypt resolve in the same TU. */
#include <linux/compiler.h>
#include <linux/bitops.h>
#undef barrier
#define barrier() do { } while (0)
#define rol32(word, shift)     (((__u32)(word) << ((shift) & 31)) | ((__u32)(word) >> ((-(shift)) & 31)))
#define ror32(word, shift)     (((__u32)(word) >> ((shift) & 31)) | ((__u32)(word) << ((-(shift)) & 31)))
#include "{ksrc}/lib/crypto/aes.c"
/* min() normally comes from linux/minmax.h; absent in this shimmed chain it
 * would become an implicit extern at aescfb.c's call sites. */
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
/* memzero_explicit is static inline in string.h but is left as an unresolved
 * extern under the BPF/gnu89 inline model (same class as rol32/ror32 above).
 * Pull string.h in first, then force call sites onto an expression macro. */
#include <linux/string.h>
#define memzero_explicit(s, n) \
	do { u8 *__mz = (u8 *)(s); unsigned int __mn = (n); \
	     while (__mn--) *__mz++ = 0; } while (0)
/* Why target.json carries -mllvm -inline-threshold=100000: aes_encrypt's
 * static internals (aes_encrypt_arch -> aes_encrypt_generic) are void
 * subprograms whose compiled bodies can exit with a stack-derived value left
 * in R0, tripping "cannot return stack pointer to the caller"; and the
 * round-key indexing walks a caller-frame array at variable offsets. Fully
 * inlined into the entry program, both issues vanish and the roundtrip
 * verifies (~14.5k insns). always_inline on the extern wrapper is NOT enough
 * (the statics stay out of line), and attributes on static forward decls are
 * ignored -- measured, see the session notes in
 * analysis/shim_completeness_and_bpf_boundaries.md. */
