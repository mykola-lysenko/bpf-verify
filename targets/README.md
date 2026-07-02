# targets/

Per-target configuration for the verification pipeline. Each directory is one
target; `pipeline.py` processes the targets listed in `ORDER`, in order.

## Layout

| Path | Purpose |
|------|---------|
| `ORDER` | Build/verification order, one target name per line. A directory not listed here is disabled but kept for future re-enablement. |
| `harness_template.c` | Shared harness skeleton. `@SRC_NAME@`, `@SRC_PATH@`, `@SAFE_NAME@`, `@HARNESS_BODY@`, `@EXTRA_INCLUDES@`, `@EXTRA_PRE_INCLUDE@`, `@EXTRA_PREAMBLE@` are replaced by the driver. |
| `_shared/*.h` | Pre-include snippets shared by several targets (referenced via `pre_include_shared`). |
| `<name>/target.json` | Target configuration, see below. |
| `<name>/harness.c` | Body of the BPF program entry point. Defaults to `return 0;` when absent. |
| `<name>/pre_include.h` | C text injected BEFORE the kernel source `#include` (macro overrides, stubs). |
| `<name>/preamble.h` | C text injected AFTER the kernel source `#include` (wrappers that need the source's types). |

## target.json

All strings may use `{ksrc}` (kernel source tree) and `{shim}` (repo `shims/`
directory) placeholders, substituted at build time.

```json
{
  "src": ["{ksrc}/lib/crc/crc16.c", "{ksrc}/lib/crc16.c"],
  "extra_includes": [["{ksrc}/lib/hweight.c"]],
  "extra_early_cflags": ["-I{shim}/lz4"],
  "extra_cflags": ["-D_LINUX_SCHED_H"],
  "pre_include_shared": ["bpf_iter_pre.h"]
}
```

- `src` — candidate source paths; the first existing one is compiled (kernel
  releases move files, e.g. `lib/crc16.c` → `lib/crc/crc16.c`).
- `extra_includes` — other translation units to `#include` before the main
  source; each entry is itself a candidate list, first existing wins.
- `extra_early_cflags` — flags inserted before the standard include paths, so
  module-specific `-I` paths can shadow the shim tree.
- `extra_cflags` — flags appended after the standard flags.
- `pre_include_shared` — snippets from `_shared/` concatenated (in order)
  before this target's own `pre_include.h`.
- `execute` — when `true`, the pipeline fuzz-executes this target after it
  verifies (Phase 3, `BPF_PROG_TEST_RUN` in the UML guest, see
  `tools/bpf_runner.c`). Requires the strict execution contract below.

## Execution contract (`execute: true`)

Load-only harnesses may return any value — veristat only checks that the
program verifies. Execution harnesses are different: the runner treats the
program's **return value as a pass/fail signal**, so they must

- return **0 on success**, and
- return non-zero **only** through `BPF_ASSERT(cond)` (which returns -1 when
  `cond` is false).

Do **not** `return` a computed value from an execution harness — it would read
as a property failure on every input. Seed inputs from `input_map` (a 4-entry
`u64` array; the runner writes fuzzed values into keys 0–3 each iteration) so
the target code stays live and is exercised with real values. Assert genuine
properties — round-trips (`decode(encode(x)) == x`), differential checks (two
implementations agree), or documented postconditions. A non-zero return on any
fuzzed input is reported by `scripts/check_results.py` as a candidate finding.
