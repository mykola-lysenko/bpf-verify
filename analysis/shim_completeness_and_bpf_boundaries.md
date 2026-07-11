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
- **Idea (future):** an `xfail`/expected-boundary annotation would let a file
  like `earlycpio.c` live in the suite as a *regression-guarded documented
  boundary* (assert it still fails with `&= on pointer prohibited`), turning a
  negative result into a durable characterization. The suite currently treats
  any non-`success` verdict as a hard error, so this needs a small mechanism
  in `scripts/check_results.py` + `target.json`.
