# BPF Verify Pipeline — Shim Fix Progress

**Date:** 2026-04-15  
**Baseline:** 50 OK, 39 FAIL  
**Current:** 69 OK, 20 FAIL  
**Net gain:** +19 targets

---

## Shims Added / Modified This Session

### 1. `shims/linux/llist.h` — Complete replacement
- **Problem:** `llist.h:239` — `xchg()` on pointer type (`struct llist_node **`) not valid in BPF.
- **Root cause:** `llist_del_all()` uses `xchg(&head->first, NULL)` which expands to `arch_xchg` with a pointer argument. The `arch_xchg` shim returns `int`, causing an incompatible integer-to-pointer conversion.
- **Fix:** Completely replaced the real `linux/llist.h` by pre-defining its include guard `LLIST_H`. Provides all the same struct/macro/inline definitions but replaces `llist_del_all` with the non-atomic `__llist_del_all` implementation (no `xchg`). Does NOT include `linux/atomic.h`.

### 2. `shims/asm/paravirt.h` — New shim (blocks real paravirt.h)
- **Problem:** `asm/paravirt.h:55` — invalid output constraint `=D` in asm (x86 register constraints not valid in BPF).
- **Root cause:** `asm/spinlock.h` → `asm/paravirt.h` → x86 inline asm with `=D` (rdi register) constraint.
- **Fix:** Created a shim that blocks the real `paravirt.h` and provides empty stubs for all paravirt functions/macros. The key insight: `CONFIG_PARAVIRT` is enabled in `autoconf.h`, so `-UCONFIG_PARAVIRT` alone was insufficient (autoconf.h re-defines it). The shim blocks the header entirely.

### 3. `shims/asm/cpufeature.h` — New shim
- **Problem:** `tsc.h:24` / `archrandom.h:50` — `cpu_feature_enabled()` and `static_cpu_has()` use `asm goto` with x86 inline asm.
- **Fix:** Created a shim that provides BPF-safe stubs: `cpu_feature_enabled(x) 0`, `static_cpu_has(x) 0`, `boot_cpu_has(x) 0`, etc. All return 0 (feature not present).

### 4. `shims/linux/uaccess.h` — New shim
- **Problem:** `linux/uaccess.h` → `linux/sched.h` → full task scheduler type system → `paravirt.h` etc.
- **Fix:** Created a shim that provides minimal `copy_from_user`/`copy_to_user` stubs without including `linux/sched.h` or `asm/uaccess.h`.

### 5. `shims/asm/barrier.h` — New shim
- **Problem:** `asm/barrier.h` uses x86 inline asm (`mfence`, `lfence`, `sfence`, `lock addl`) not valid in BPF. `asm/atomic.h` uses `smp_load_acquire`/`smp_store_release` which come from `asm/barrier.h`.
- **Fix:** Created a shim with BPF-safe no-op stubs for all memory barrier primitives (`mb()`, `rmb()`, `wmb()`, `__smp_load_acquire`, `__smp_store_release`, etc.). Includes `asm-generic/barrier.h` for the public `smp_load_acquire`/`smp_store_release` macros.
- **Also:** Added `#include <asm/barrier.h>` to `shims/asm/atomic.h` so `smp_load_acquire` is available when `atomic.h` is included.

### 6. `shims/asm/pgtable_types.h` — New shim
- **Problem:** `linux/mm_types.h:158` — `unknown type name 'pgtable_t'`. `mm_types.h` uses `pgtable_t` inside `struct page` definition, but `pgtable_t` is defined in `asm/pgtable_types.h` which was never included.
- **Root cause:** In the real kernel, `asm/processor.h` includes `asm/pgtable_types.h`. Our `shims/asm/processor.h` didn't include it.
- **Fix:** Created `shims/asm/pgtable_types.h` with minimal type stubs (`pgtable_t`, `pgprot_t`, `pgd_t`, `pud_t`, `pmd_t`, `pte_t`). Note: `pgtable_t` is defined as `void *` (not `struct page *`) to break the circular dependency with `struct page`. Added `#include <asm/pgtable_types.h>` to `shims/asm/processor.h`.

### 7. `pipeline.py` harness template — `#undef CONFIG_NUMA` / `#undef CONFIG_PARAVIRT`
- **Problem:** `-UCONFIG_NUMA` and `-UCONFIG_PARAVIRT` command-line flags were being overridden by `generated/autoconf.h` (included via `kconfig.h` force-include). The `autoconf.h` re-defines `CONFIG_NUMA 1` and `CONFIG_PARAVIRT 1` AFTER the `-U` flags are processed.
- **Fix:** Added `#undef CONFIG_NUMA` and `#undef CONFIG_PARAVIRT` at the very top of the harness template (before any kernel headers are included). These `#undef` directives in the source file take effect after `autoconf.h` has been processed, effectively overriding the autoconf definitions.

---

## Remaining Failures (20 targets)

| Target | Error | Category |
|--------|-------|----------|
| `llist` | `llist.c:33: incompatible integer to pointer (try_cmpxchg on pointer)` | xchg/cmpxchg on pointer |
| `errseq` | `errseq.c:74: statement requires expression` | `asm goto` / complex statement expr |
| `find_bit` | `unimplemented opcode: 191` | BPF backend CTTZ opcode |
| `int_sqrt` | `unimplemented opcode: 192` | BPF backend CTLZ opcode |
| `clz_ctz` | `unimplemented opcode: 191` | BPF backend CTTZ opcode |
| `crc32` | `sched.h:1538: field has incompatible type` | `sched.h` deep type system |
| `seq_buf` | `sched.h:1538: field has incompatible type` | `sched.h` deep type system |
| `kstrtox` | `use of undeclared identifier` | missing stub |
| `siphash` | `word-at-a-time.h:85: invalid` | x86 inline asm |
| `packing` | `stack arguments are not supported` | BPF stack limit |
| `zstd_entropy_common` | `stack arguments are not supported` | BPF stack limit |
| `zstd_fse_decompress` | `use of undeclared identifier` | missing stub |
| `zstd_huf_decompress` | `0 is not a valid value` | BPF constraint |
| `zstd_decompress` | various | complex zstd |
| `lz4_decompress` | `stack arguments are not supported` | BPF stack limit |
| `lz4_compress` | `stack arguments are not supported` | BPF stack limit |
| `lzo_compress` | `missing file` | missing generated header |
| `mpi_mul` | `missing file` | missing generated header |
| `crc64` | `crc64table.h not found` | missing generated header |
| `dim` | `ktime.h:155: unsupported sign` | BPF arithmetic |

### Next Steps (in priority order)

1. **`llist.c:33`** — `try_cmpxchg` on `struct llist_node **` pointer. Need to add `try_cmpxchg` stub for pointer types in `shims/asm/cmpxchg.h`.

2. **`sched.h:1538`** (crc32, seq_buf) — `field has incompatible type`. The `sched.h` is being pulled in despite `uaccess.h` shim. Need to trace the new include chain.

3. **`kstrtox`** — `use of undeclared identifier`. Quick fix once identified.

4. **`siphash`** — `word-at-a-time.h:85`. Need `shims/asm/word-at-a-time.h`.

5. **`errseq`** — `asm goto` statement. Need to stub out the cmpxchg loop.

6. **`dim`** — `ktime.h:155: unsupported sign`. Quick fix.

7. **`find_bit`/`int_sqrt`/`clz_ctz`** — BPF backend opcodes 191/192. These are `__builtin_ctz`/`__builtin_clz` — need `-DCONFIG_CPU_NO_EFFICIENT_FFS` or loop-based fallbacks.

8. **`packing`/`lz4_*`/`zstd_*`** — Stack argument issues. These are deep BPF stack size limits (512 bytes). May need restructuring or are fundamentally incompatible.

9. **`crc64`/`lzo_compress`/`mpi_mul`** — Missing generated headers. Need to either generate them or provide stubs.
