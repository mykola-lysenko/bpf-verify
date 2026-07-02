/* Include cmpxchg.h so arch_cmpxchg is defined as a macro (not an extern).
 * The renamed llist.c functions (__llist_add_batch_atomic etc.) use try_cmpxchg
 * which expands to arch_cmpxchg via atomic-arch-fallback.h. Without this include,
 * arch_cmpxchg would appear as an unresolved extern in BTF, causing libbpf to
 * fail to load the BPF object. */
#include <asm/cmpxchg.h>
/* Rename llist.c functions to avoid conflict with shim static inline versions.
 * The shim provides non-atomic implementations to work around try_cmpxchg on
 * pointer types (not supported in BPF context). */
#define llist_add_batch     __llist_add_batch_atomic
#define llist_del_first     __llist_del_first_atomic
#define llist_reverse_order __llist_reverse_order_impl
