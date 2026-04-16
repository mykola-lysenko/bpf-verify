# `always_inline` Audit — Classification of Every Shim Function

Rules:
- `always_inline` REQUIRED: function returns struct by value, OR has >5 args, OR calls another function that requires always_inline (call chain)
- `static inline` SUFFICIENT: scalar/void return, ≤5 args, no struct-return callees

---

## tnum-shim.c
ALL functions return `struct tnum` by value → ALL require `always_inline`. No changes.

---

## lpm_trie-shim.c

| Function | Return | Args | Calls struct-return? | Verdict |
|---|---|---|---|---|
| `fls(unsigned int x)` | `int` | 1 | No | `static inline` sufficient |
| `fls64(u64 x)` | `int` | 1 | No | `static inline` sufficient |
| `be32_to_cpu(u32 x)` | `u32` | 1 | No | `static inline` sufficient |
| `be16_to_cpu(u16 x)` | `u16` | 1 | No | `static inline` sufficient |
| `be64_to_cpu(u64 x)` | `u64` | 1 | No | `static inline` sufficient |
| `__lpm_memcpy(void*, const void*, size_t)` | `void*` | 3 | No | `static inline` sufficient |
| `ERR_PTR(long error)` | `void*` | 1 | No | `static inline` sufficient |
| `IS_ERR(const void*)` | `bool` | 1 | No | `static inline` sufficient |

All lpm_trie helpers have scalar/pointer returns and ≤3 args. None call struct-returning functions.
→ **All 8 can be downgraded from `always_inline` to `static inline`.**

The actual trie algorithm functions (`extract_bit`, `longest_prefix_match`, `trie_lookup_elem`, etc.) are already plain `static` or `static inline` — no change needed.

---

## bloom_filter-shim.c

| Function | Return | Args | Calls struct-return? | Verdict |
|---|---|---|---|---|
| `bloom_filter_init(struct bpf_bloom_filter*, u32, u32)` | `void` | 3 | No | `static inline` sufficient |
| `bloom_test_bit(u64*, u32)` | `int` | 2 | No | `static inline` sufficient |
| `bloom_set_bit(u64*, u32)` | `void` | 2 | No | `static inline` sufficient |
| `bloom_hash(struct bpf_bloom_filter*, void*, u32)` | `u32` | 3 | No | **KEEP `always_inline`** — calls `jhash`/`jhash2` which are large and may not be inlined; without `always_inline` on `bloom_hash` itself, the compiler may leave it as a BPF_CALL, and the verifier then sees a variable-offset result it cannot bound (this was the original failure) |
| `bloom_map_peek_elem(struct bpf_bloom_filter*, void*)` | `int` | 2 | No | **KEEP `always_inline`** — calls `bloom_hash` in a loop; if not inlined, the verifier sees a BPF_CALL with variable return value |
| `bloom_map_push_elem(struct bpf_bloom_filter*, void*, u64)` | `int` | 3 | No | **KEEP `always_inline`** — same reason as peek_elem |

→ **`bloom_filter_init`, `bloom_test_bit`, `bloom_set_bit` can be downgraded to `static inline`.**
→ **`bloom_hash`, `bloom_map_peek_elem`, `bloom_map_push_elem` must keep `always_inline`** (the verifier needs to see the bounded bit-index arithmetic inline, not through a call).

---

## bpf_lru_list-shim.c

### List primitives (lines 82–134)

| Function | Return | Args | Verdict |
|---|---|---|---|
| `INIT_LIST_HEAD(struct list_head*)` | `void` | 1 | `static inline` sufficient |
| `list_empty(const struct list_head*)` | `int` | 1 | `static inline` sufficient |
| `__list_add(struct list_head*, struct list_head*, struct list_head*)` | `void` | 3 | `static inline` sufficient |
| `list_add(struct list_head*, struct list_head*)` | `void` | 2 | `static inline` sufficient |
| `list_add_tail(struct list_head*, struct list_head*)` | `void` | 2 | `static inline` sufficient |
| `__list_del(struct list_head*, struct list_head*)` | `void` | 2 | `static inline` sufficient |
| `list_del(struct list_head*)` | `void` | 1 | `static inline` sufficient |
| `list_move(struct list_head*, struct list_head*)` | `void` | 2 | `static inline` sufficient |

### Node/list helpers (lines 221–344)

| Function | Return | Args | Verdict |
|---|---|---|---|
| `bpf_lru_node_set_ref(struct bpf_lru_node*)` | `void` | 1 | `static inline` sufficient |
| `local_free_list(struct bpf_lru_locallist*)` | `struct list_head*` | 1 | `static inline` sufficient |
| `local_pending_list(struct bpf_lru_locallist*)` | `struct list_head*` | 1 | `static inline` sufficient |
| `bpf_lru_node_is_ref(const struct bpf_lru_node*)` | `bool` | 1 | `static inline` sufficient |
| `bpf_lru_node_clear_ref(struct bpf_lru_node*)` | `void` | 1 | `static inline` sufficient |
| `bpf_lru_list_count_inc(struct bpf_lru_list*, enum)` | `void` | 2 | `static inline` sufficient |
| `bpf_lru_list_count_dec(struct bpf_lru_list*, enum)` | `void` | 2 | `static inline` sufficient |
| `bpf_lru_list_inactive_low(const struct bpf_lru_list*)` | `bool` | 1 | `static inline` sufficient |

### Core algorithm functions (lines 285–510)

These are the complex, multi-level functions. They call each other and the list primitives above. The concern is whether the compiler will inline them at `-O2`.

| Function | Return | Args | Body size | Verdict |
|---|---|---|---|---|
| `__bpf_lru_node_move_to_free(l, node, free_list, type)` | `void` | 4 | ~10 lines | **KEEP `always_inline`** — called from loop-containing functions; LLVM at -O2 may emit as a separate `.text` function, causing a BPF_CALL that the verifier rejects |
| `__bpf_lru_node_move_in(l, node, type)` | `void` | 3 | ~8 lines | **KEEP `always_inline`** — same reason: called from `__local_list_flush` (loop) |
| `__bpf_lru_node_move(l, node, type)` | `void` | 3 | ~12 lines | **KEEP `always_inline`** — same reason: called from `_rotate_active` and `_rotate_inactive` (loops) |
| `__bpf_lru_list_rotate_active(lru, l)` | `void` | 2 | ~15 lines, loop | **KEEP `always_inline`** — contains a loop + multiple calls; compiler may not inline |
| `__bpf_lru_list_rotate_inactive(lru, l)` | `void` | 2 | ~20 lines, loop | **KEEP `always_inline`** — same reason |
| `__bpf_lru_list_shrink_inactive(lru, l, n, free, type)` | `unsigned int` | 5 | ~20 lines, loop | **KEEP `always_inline`** — 5 args at the limit, loop |
| `__bpf_lru_list_rotate(lru, l)` | `void` | 2 | ~4 lines | `static inline` — tiny wrapper |
| `__local_list_flush(l, loc_l)` | `void` | 2 | ~8 lines, loop | **KEEP `always_inline`** — loop |
| `bpf_lru_list_init(l)` | `void` | 1 | ~8 lines | `static inline` sufficient |
| `bpf_lru_locallist_init(loc_l, cpu)` | `void` | 2 | ~6 lines | `static inline` sufficient |
| `bpf_lru_list_populate(l, nodes, nr_elems)` | `void` | 3 | ~8 lines, loop | **KEEP `always_inline`** — loop |
| `bpf_lru_list_alloc(l)` | `struct bpf_lru_node*` | 1 | ~10 lines | `static inline` sufficient |

---

## Summary of Changes

| Shim | Functions to downgrade | Functions to keep `always_inline` |
|---|---|---|
| `tnum-shim.c` | 0 (all return struct) | All 16 |
| `lpm_trie-shim.c` | 8 utility helpers | 0 |
| `bloom_filter-shim.c` | 3 (`init`, `test_bit`, `set_bit`) | 3 (`hash`, `peek`, `push`) |
| `bpf_lru_list-shim.c` | 14 (list primitives + small helpers) | 8 (loop-containing + callee functions) |
