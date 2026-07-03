#!/usr/bin/env python3
"""Build the BPF side of a native-vs-BPF differential target.

Reuses the pipeline's exact BPF compilation for targets/<name> (same shim
tree, cflags, includes) but swaps in the differential harness body from
diff/<name>/harness.c and injects diff/<name>/compute.h at file scope (so the
shared diff_compute() can call the kernel function). Emits <name>_diff.bpf.o.

Usage: diff_build.py <name> [--out DIR]
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import pipeline

DIFF_DIR = Path(__file__).parent.parent / "diff"

# Standard differential harness body: read the 4 map inputs and return a 32-bit
# fold of the 64-bit diff_compute() result via the program return value. A
# target only needs a compute.h (+ native.flags); override with a per-target
# harness.c if it needs something else.
DEFAULT_DIFF_BODY = """\
    __u32 k;
    __u64 in[4];
    __u64 *p;
    k = 0; p = bpf_map_lookup_elem(&input_map, &k); in[0] = p ? *p : 0;
    k = 1; p = bpf_map_lookup_elem(&input_map, &k); in[1] = p ? *p : 0;
    k = 2; p = bpf_map_lookup_elem(&input_map, &k); in[2] = p ? *p : 0;
    k = 3; p = bpf_map_lookup_elem(&input_map, &k); in[3] = p ? *p : 0;
    __u64 r = diff_compute(in);
    return (int)(__u32)(r ^ (r >> 32));
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("--out", type=Path, default=pipeline.OUTPUT)
    args = ap.parse_args()

    name = args.name
    tdir = DIFF_DIR / name
    compute = tdir / "compute.h"
    if not compute.exists():
        sys.exit(f"diff/{name}/compute.h not found")

    cfg = pipeline.load_target(name)          # real BPF build config
    body = tdir / "harness.c"
    cfg["harness_body"] = body.read_text() if body.exists() else DEFAULT_DIFF_BODY
    # compute.h at file scope, after the kernel source include, so
    # diff_compute() can reference the target's functions
    cfg["preamble"] = cfg.get("preamble", "") + "\n" + compute.read_text()

    src = pipeline.resolve_candidates(cfg["src"])
    if not src.exists():
        sys.exit(f"source not found: {src}")

    args.out.mkdir(parents=True, exist_ok=True)
    out = args.out / f"{name}_diff.bpf.o"
    ok, errors = pipeline.compile_harness(name, src, cfg, out)
    if not ok:
        print(f"[FAIL] {name}_diff:")
        for e in errors[:20]:
            print(f"  {e}")
        sys.exit(1)
    print(f"[OK] {out}")


if __name__ == "__main__":
    main()
