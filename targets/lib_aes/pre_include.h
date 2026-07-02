
/* The kernel rotate helpers are static inline but can be left as unresolved
 * externs under the BPF/gnu89 inline model. Include their definitions first,
 * then force AES call sites to use expression macros. */
#include <linux/compiler.h>
#include <linux/bitops.h>
#undef barrier
#define barrier() do { } while (0)
#define rol32(word, shift)     (((__u32)(word) << ((shift) & 31)) | ((__u32)(word) >> ((-(shift)) & 31)))
#define ror32(word, shift)     (((__u32)(word) >> ((shift) & 31)) | ((__u32)(word) << ((-(shift)) & 31)))
