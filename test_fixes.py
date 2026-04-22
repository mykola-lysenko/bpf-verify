#!/usr/bin/env python3
"""Test the three failing targets: base64, min_heap, union_find."""
import os
import subprocess
import sys
sys.path.insert(0, '/home/ubuntu/bpf-verify')
import pipeline

# Candidates dict from main()
from pathlib import Path
KSRC = pipeline.KSRC
SHIM = pipeline.SHIM
OUTPUT = pipeline.OUTPUT

candidates = {
    "base64":     KSRC / "lib/base64.c",
    "min_heap":   KSRC / "lib/min_heap.c",
    "union_find": KSRC / "lib/union_find.c",
}

for name, src in candidates.items():
    print(f'=== Testing {name} ===')
    if not src.exists():
        print(f'  [SKIP] source not found: {src}')
        continue

    harness_body = pipeline.HARNESS_BODIES.get(name, pipeline.DEFAULT_HARNESS_BODY)
    out = OUTPUT / f"{name}.bpf.o"

    ok, errors = pipeline.compile_harness(name, src, harness_body, out)
    if not ok:
        print(f'  COMPILE FAILED:')
        for e in errors[:5]:
            print(f'    {e}')
        continue
    print(f'  Compile OK: {out}')

    # Run veristat
    veristat_cmd = [str(pipeline.VERISTAT)]
    if os.environ.get("BPF_VERISTAT_SUDO", ""):
        veristat_cmd = ["sudo"] + veristat_cmd
    r = subprocess.run(veristat_cmd + [str(out)],
                      capture_output=True, text=True, timeout=60)
    print(r.stdout.strip())
    if r.returncode != 0:
        print('VERISTAT STDERR:', r.stderr[-200:])
    print()
