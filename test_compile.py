#!/usr/bin/env python3
"""Compile (and optionally verify) individual targets to diagnose errors.

Usage:
  python3 test_compile.py <target> [<target> ...] [--veristat]

Targets are directory names under targets/ (e.g. "string", "mpi_add").
"""
import argparse
import os
import subprocess
import sys

import pipeline


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="+", help="target names (targets/<name>)")
    parser.add_argument("--veristat", action="store_true",
                        help="run veristat on each successfully compiled object")
    args = parser.parse_args()

    failed = False
    for name in args.targets:
        print(f"=== {name} ===")
        try:
            cfg = pipeline.load_target(name)
        except SystemExit as e:
            print(f"  [FAIL] {e}")
            failed = True
            continue
        if "src" not in cfg:
            print("  [SKIP] no src in target.json (disabled target)")
            continue
        src = pipeline.resolve_candidates(cfg["src"])
        if not src.exists():
            print(f"  [SKIP] source not found: {src}")
            continue

        out = pipeline.OUTPUT / f"{name}.bpf.o"
        ok, errors = pipeline.compile_harness(name, src, cfg, out)
        if not ok:
            failed = True
            print("  COMPILE FAILED:")
            for e in errors[:20]:
                print(f"    {e}")
            continue
        print(f"  Compile OK: {out}")
        for e in errors:
            print(f"    {e}")

        if args.veristat:
            veristat_cmd = [str(pipeline.VERISTAT)]
            if os.environ.get("BPF_VERISTAT_SUDO", ""):
                veristat_cmd = ["sudo"] + veristat_cmd
            r = subprocess.run(veristat_cmd + [str(out)],
                               capture_output=True, text=True, timeout=60)
            print(r.stdout.strip())
            if r.returncode != 0:
                failed = True
                print("  VERISTAT STDERR:", r.stderr[-200:])
        print()

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
