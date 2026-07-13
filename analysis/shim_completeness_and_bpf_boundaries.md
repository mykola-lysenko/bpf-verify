# Shim completeness vs. BPF verifier boundaries

Two distinct things gate whether a `lib/` source file becomes a verified target:

1. **Does it compile to BPF at all?** — gated by *shim completeness* (are the
   kernel infra types/headers it pulls in available in our standalone shim
   tree?). This is a pipeline-side problem we can fix.
2. **Does the compiled program verify?** — gated by *BPF verifier boundaries*
   (pointer alignment, indirect calls, complexity, stack). This is intrinsic to
   the kernel source + the verifier; we cannot shim around it.

This note records a batch that pushed on (1) and what it revealed about (2).

## Shim additions (compilation unlocked: 9 -> 18 buildable lib files)

Measured over the untargeted `lib/` candidate set with a trivial `return 0`
harness (compile-only probe), on clang-23:

| Shim change | Effect |
|-------------|--------|
| `vm_area_struct.vm_file` + `struct file`/`vm_area_desc` fwd decls | `fs.h` inline helpers type-check; blocker 11 -> 3 files (+8 buildable) |
| `vm_area_struct.vm_ops` + `vm_operations_struct` fwd decl | `mm.h` inline helpers type-check |
| `linux/shm.h` minimal stub | blocks the real header whose `-ENOSYS` static inline lacks `errno.h` in a standalone build; SysV shm is never used by lib code |

Net: **9 -> 18** buildable, untargeted `lib/` files. No regression: the existing
214 targets still verify. (Commit: shim completeness batch.)

### Remaining compile blockers (deeper / moving targets, not pursued)

| Blocker | Files | Nature |
|---------|-------|--------|
| BPF-backend stack/complexity | 7 | genuine — the file itself is too big/complex |
| `srcutree.h` `struct irq_work` incomplete type | 5 | forward-decl: srcutree.h uses `struct irq_work` without including its header |
| `smp.h` `cpu_llc_shared_map` | 5 | x86 topology global |
| `mm.h` `vma->flags` | 3 | recent `struct vma_flags` MM refactor (moving target) |
| `msr.h` / `skcipher.h` / `hash.h` / `vmalloc.h` | 1 each | singletons |

### A second mining pass (attempted, then reverted): these are deep chains, not one-liners

Unlike the first batch (single missing struct members / trivial header stubs),
every remaining blocker turned out to be a deep multi-header chain or genuinely
unshimmable. Documented here so the next attempt knows the terrain:

- **`srcutree.h` `irq_work` (5 files) — fixable, but not a clean win.** srcutree.h
  embeds `struct irq_work` by value without including its header. The fix (a shim
  `irq_work_types.h` with the real `_LINUX_IRQ_WORK_TYPES_H` guard, force-included
  early so the type is always complete) *works* for compilation, but:
  1. It **regresses 3 existing targets** (`task_iter`, `ringbuf_prove`,
     `ringbuf_lifecycle_prove`) that define *and use* their own `struct irq_work`
     with specific members (`.func`, `.queued`, `.busy`). A global `irq_work` is
     fundamentally incompatible with per-target custom definitions — guarding
     their local defs just swaps in the opaque shim struct, which lacks the
     members their code reads. A *targeted* shim of `srcutree.h` (via
     `#include_next`) would avoid the global conflict, but see (2).
  2. It **unlocks nothing on its own.** The 5 srcutree files immediately hit the
     next wall: `mm.h`, which is a chain of its own —
     `vma_flags` refactor → `struct vm_area_desc` (embeds `struct mmap_action`) →
     `struct vma_iterator` (embeds `struct ma_state`, i.e. the **maple tree**) →
     … Each level is individually shimmable (the `vma_flags` mini-API is ~8
     primitive inlines over a one-long bitmap; `vm_area_desc`/`mmap_action` are
     plain structs), but the chain bottoms out in the maple-tree API (declare
     `mas_find`/`mas_next_range`/… + an opaque `ma_state`). Completing all of it
     is a large surface for an uncertain payoff.
- **`smp.h` `cpu_llc_shared_map` (5 files)** — x86 per-CPU machinery
  (`DECLARE_PER_CPU_READ_MOSTLY` + `per_cpu(...)` in an inline). Needs the
  per-CPU infrastructure, not a one-liner.
- **`vmalloc.h` `pgprot_t` (generic-radix-tree.c)** — `vmalloc.h` expects
  `pgprot_t` from `asm/page.h`, but some shimmed header in that transitive chain
  breaks the path. Another include-chain investigation.
- **`io.h` `=a` inline-asm constraint (iomap_copy.c)** — genuine x86 inline
  assembly; **not shimmable** (BPF has no inline asm target for it).
- **`string_64.h` conflicting `memset` (group_cpus.c)** — a `memset` declaration
  clash between the arch header and our harness stubs.

**Conclusion of the second pass:** the high-leverage shim wins (struct members,
trivial header stubs) are exhausted at 9→18. What remains is deep kernel
infrastructure (maple tree, per-CPU, the `pgprot_t` include chain) or
unshimmable x86 asm — and the files behind these mostly hit BPF verifier
boundaries when exercised anyway (see below). The second-pass edits were reverted
to keep the suite green; this section records the terrain so the effort isn't
repeated blind.

### Third pass: deliberately completing the mm.h chain (mapped in full, then reverted)

A focused attempt to finish the srcutree → mm.h chain and land `bitmap-str.c`
(`bitmap_parselist`) as a coverage target. It got all the way to the verifier,
which is the useful result: it maps the true depth and shows where it bottoms
out. Reverted to keep the suite green; recorded here so the next attempt is
informed.

**The srcutree/irq_work blocker is cleanly solvable (targeted, no regression).**
A `srcutree.h` shim (`#include <linux/irq_work.h>` then `#include_next`) plus an
`irq_work_types.h` split (opaque `struct irq_work` under the real
`_LINUX_IRQ_WORK_TYPES_H` guard) completes the type *only* for TUs that pull
srcu — so, unlike the global force-include, it does NOT regress the 3 targets
that define their own `irq_work`. This part works and is worth reviving if the
rest is ever pursued.

**Completing mm.h standalone is a large surface, but each level is mechanical.**
Reaching a compilable `mm.h` required, in order:
- the `vma_flags` mini-API (8 primitive inlines over a one-long bitmap +
  `EMPTY_VMA_FLAGS`/`NUM_VMA_FLAG_BITS`) and a `flags` member on `vm_area_struct`;
- complete `struct vm_area_desc` + `struct mmap_action` + `enum mmap_action_type`;
- `struct vma_iterator` — just include the **real** `linux/maple_tree.h` (it
  compiles here; shadowing it minimally instead *regresses* 8 fs.h files that
  embed `struct maple_tree` by value);
- three large-folio union arms on `struct folio` (`_flags_1/_2/_3`,
  `_large_mapcount`, `_entire_mapcount`, `_pincount`, `_nr_pages`, `_mm_ids`,
  `_last_cpupid`);
- `-DZERO_PAGE(vaddr)=((struct page *)0)` (huge_mm.h uses it behind blocked
  pgtable.h);
- guarding gfp.h's `folio_put`/`folio_alloc` stubs with `#ifndef _LINUX_MM_H`
  (mm.h owns them) — but this is **include-order-fragile**: 5 files that pull
  gfp.h *before* mm.h still clash;
- `mm_struct` members `mm_mt` (maple_tree), `write_protect_seq` (seqcount),
  `pgtables_bytes` (atomic_long), `rss_stat` (`percpu_counter[NR_MM_COUNTERS]`) …
  and the chain kept going. **It does not bottom out quickly** — mm.h is one of
  the deepest headers in the tree.

**The lighter shortcut — block mm.h for parser files — works to compile, but
the target then bottoms out in BPF boundaries.** `bitmap-str.c` pulls mm.h only
for `kasprintf` in an unexercised sysfs helper, so `#define _LINUX_MM_H` (block
it) compiles far more cheaply. But making `bitmap_parselist` *load and verify*
required reimplementing its lib dependency web — `_ctype` (via `lib/ctype.c`),
`_parse_integer` (hand-written 64-bit; the real `lib/kstrtox.c` needs `__multi3`
128-bit multiply, **unavailable on BPF**), `__bitmap_set`/`__bitmap_clear`/
`_find_next_bit`, `strnchrnul`/`strncasecmp`/`strlen`/`memset`, plus `min` and a
variadic-swallowing `kasprintf` macro (~11 symbols). And after all that it still
fails the verifier two ways:
- minimal build → **`cannot return stack pointer to the caller`** (the static
  helpers `bitmap_find_region`/`bitmap_getnum`/`bitmap_parse_region` return a
  `const char*` cursor into the caller's stack buffer; `always_inline`/`flatten`
  on forward-decls were silently ignored by clang here);
- force-inlined (`-inline-threshold=100000`) → **"sequence of 8193 jumps is too
  complex"** (verifier jump-complexity limit).

**Conclusion of the third pass.** The srcutree/irq_work fix is clean; the mm.h
chain is completable but is a large, partly include-order-fragile surface that
doesn't converge quickly; and the one genuinely promising parser behind it
(`bitmap_parselist`) needs ~11 lib reimplementations and *still* hits BPF
boundaries (stack-pointer return, then jump complexity). So "complete the mm.h
chain to land these files" is not a good ROI: the destination files are boundary
-bound even once compiled. The high-value work remains elsewhere (the existing
214 targets; pure scalar/bounded-array compute).

## Buildable != verifiable: the boundaries the new files hit

Making a file *compile* does not make it *verify*. Sampling the newly-buildable
files by writing a real harness that exercises the file's natural entry point
shows the dominant blocker shifts from **shim/header gaps (now solved)** to
**genuine BPF verifier boundaries**:

| File | Entry point | Verifier boundary hit |
|------|-------------|-----------------------|
| `lib/earlycpio.c` | `find_cpio_data` | **`R4 bitwise operator &= on pointer prohibited`** — `PTR_ALIGN(p + namesize, 4)` aligns a *pointer* via `& ~mask`; the verifier forbids bitwise ops on pointers |
| `lib/bch.c` | `bch_encode` | 4 `ALIGN`/pointer-mask sites (same PTR_ALIGN class) + needs a fully-initialized `bch_control` table |
| `lib/ts_bm.c` | `bm_find` | textsearch dispatches text via `state->get_next_block(...)` — an **indirect call** through a struct function pointer |
| `lib/decompress.c` | `decompress_method` | returns a `decompress_fn` from a **function-pointer table** (`compressed_formats[]`) — function pointers in data, awkward/unsupported in BPF |

`find_cpio_data` was carried furthest: it compiled (after `strlen`/`memcmp`/
`sized_strscpy` inline shims — `strscpy` expands to `sized_strscpy`, which would
otherwise be an unresolved extern that blocks the object load) and reached the
verifier, which rejected it at the `PTR_ALIGN` site with the exact diagnostic
above. That is a clean, reproducible, benign characterization — a real BPF
verifier boundary in unmodified kernel source, not a pipeline gap.

## Takeaways

- **Shim completeness is a genuine force-multiplier for *compilation* breadth**
  and worth continuing (the `vm_area_struct` completion doubled the buildable
  set from one small struct change).
- But for these particular parser/search/dispatch files, *verification* is
  blocked by intrinsic BPF boundaries (`PTR_ALIGN` on pointers, indirect
  callbacks, function-pointer tables), which no shim can remove. The clean
  coverage-target candidates are pure scalar / bounded-array compute functions,
  not pointer-aligning parsers.
- **Update — this mechanism now exists.** `"expect_failure": "<verifier
  message>"` in `target.json` makes a target a *regression-guarded documented
  boundary*: the pipeline captures the verifier log (`capture_verifier_log`)
  and `check_results.py` requires the target to fail *with that diagnostic* —
  verifying successfully (boundary lifted upstream) or failing with a different
  message are both hard CI errors.

## The boundary catalog (documented-boundary targets)

Four distinct verifier-boundary classes hit by unmodified kernel source, each
pinned as a live `expect_failure` target:

| Target | Kernel idiom | Verifier diagnostic |
|--------|--------------|---------------------|
| `find_cpio_data` | `PTR_ALIGN(p + off, 4)` — pointer alignment via bitwise AND | `bitwise operator &= on pointer prohibited` |
| `bitmap_parselist` | parse helper returns a `const char*` cursor into the caller's buffer | `cannot return stack pointer to the caller` (force-inlined instead: 8192-jump complexity limit) |
| `bm_find` (ts_bm) | callback through a struct function pointer (`conf->get_next_block(...)`) — the standard kernel ops-table idiom | `unknown opcode 8d` (clang emits the indirect-call `callx` insn; the verifier rejects the opcode outright) |
| `int_sqrt_global` | `EXPORT_SYMBOL` scalar function verified as a **global function** (`.BTF.ext` kept) — all-inputs verification of its bit loop | `BPF program is too large. Processed 1000001 insn` (the same function verifies easily as a static subprogram — see the plain `int_sqrt` target) |

Findings that fell out of building these:

- **clang devirtualizes single-candidate callbacks.** With one statically-known
  `get_next_block`, clang constant-propagates the callee, inlines it, and the
  ts_bm program *verifies* (10 insns). The `callx` boundary only manifests when
  the callback is genuinely runtime-selected (the target picks between two
  candidates via a map value). So "kernel code with callbacks" is not uniformly
  outside BPF — monomorphic callback sites compile away.
- **Taking a function's address needs func-info.** With `.BTF.ext` stripped
  (pipeline default), `&func` fails earlier with `missing btf func_info` — an
  artifact of our strip, not an intrinsic boundary; the `bm_find` target keeps
  `.BTF.ext` to pin the real one.
- **`asn1_ber_decoder` is callx-bound (confirmed, not pinned).** Its action
  dispatch is a runtime-indexed function-pointer table
  (`actions[act](context, ...)` at three sites) — probed with a minimal
  machine + stub action table (`.BTF.ext` kept): rejected with
  `unknown opcode 8d` after 0 insns, the same indirect-call class `bm_find`
  pins. The BER parser itself is out of reach until the verifier accepts
  indirect calls; a duplicate pin adds nothing.
- **`decompress_method` is NOT pinnable as a distinct boundary.** With our
  autoconf, `decompress.c` `#define`s every absent `CONFIG_DECOMPRESS_*`
  decompressor to `NULL`, so `compressed_formats[]` holds no function pointers
  at all; and calling through a table-loaded pointer would hit the same `callx`
  class `bm_find` already pins.
- The `int_sqrt` / `int_sqrt_global` pair turns the global-function
  all-inputs-vs-concrete-context trade (analysis/global_functions_and_inlining
  .md) into a CI-checked artifact.
