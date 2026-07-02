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
