#!/usr/bin/env python3
"""Gate pipeline results and compare them against the committed baseline.

Usage:
  scripts/check_results.py <results.json> [--baseline baseline/results.json]
                           [--update-baseline]

Hard failures (exit 1):
  - any target failed to compile
  - veristat ran but produced no verdict for a compiled target
    (object could not be opened / program skipped)
  - any program got a "failure" verdict
  - a baseline target is missing from the results, or its verdict regressed
  - a new target is not in the baseline (run with --update-baseline and
    commit the refreshed baseline together with the new target)

Instruction-count drift that is not a collapse is reported but not fatal.
"""
import argparse
import json
import sys
from pathlib import Path

errors = []
warnings = []


def error(msg):
    errors.append(msg)
    print(f"::error::{msg}")


def warn(msg):
    warnings.append(msg)
    print(f"::warning::{msg}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path)
    parser.add_argument("--baseline", type=Path,
                        default=Path(__file__).parent.parent / "baseline" / "results.json")
    parser.add_argument("--update-baseline", action="store_true",
                        help="write the results as the new baseline instead of comparing")
    args = parser.parse_args()

    results = json.loads(args.results.read_text())
    targets = results["targets"]
    veristat_ran = results.get("veristat_ran", False)

    # --- Absolute gates (no baseline needed) ---------------------------------
    for name, t in sorted(targets.items()):
        if not t.get("compiled"):
            error(f"{name}: compile failed: {t.get('error', 'unknown error')}")
        elif veristat_ran and t.get("verdict") is None:
            error(f"{name}: no veristat verdict (object skipped or failed to open)")
        elif veristat_ran and t.get("verdict") != "success":
            error(f"{name}: verifier verdict is {t.get('verdict')!r}")

    stderr = results.get("veristat_stderr", "")
    for line in stderr.splitlines():
        if "Failed to open" in line:
            error(f"veristat: {line.strip()}")

    # --- Baseline update -----------------------------------------------------
    if args.update_baseline:
        if errors:
            print(f"\nNot updating baseline: {len(errors)} error(s) above.")
            return 1
        args.baseline.parent.mkdir(parents=True, exist_ok=True)
        baseline = {
            "schema": results["schema"],
            "targets": {
                name: {k: t[k] for k in ("verdict", "insns", "states") if k in t}
                for name, t in sorted(targets.items())
            },
        }
        args.baseline.write_text(json.dumps(baseline, indent=2) + "\n")
        print(f"Baseline updated: {args.baseline} ({len(targets)} targets)")
        return 0

    # --- Baseline comparison --------------------------------------------------
    if not args.baseline.exists():
        warn(f"no baseline at {args.baseline}; skipping comparison "
             f"(create one with --update-baseline)")
    elif not veristat_ran:
        warn("veristat did not run; skipping baseline comparison")
    else:
        baseline = json.loads(args.baseline.read_text())["targets"]
        drift = []
        for name, b in sorted(baseline.items()):
            t = targets.get(name)
            if t is None:
                error(f"{name}: in baseline but missing from results "
                      f"(source not found / removed from targets/ORDER?)")
                continue
            if not t.get("compiled") or t.get("verdict") != "success":
                continue  # already reported by the absolute gates
            b_insns, t_insns = b.get("insns"), t.get("insns")
            if b_insns and t_insns is not None and t_insns != b_insns:
                drift.append(f"{name}: insns {b_insns} -> {t_insns}")
        for name in sorted(set(targets) - set(baseline)):
            error(f"{name}: not in baseline; run scripts/check_results.py "
                  f"--update-baseline and commit the refreshed baseline")
        if drift:
            print(f"\nInstruction-count drift ({len(drift)} targets, non-fatal):")
            for line in drift:
                print(f"  {line}")

    n_ok = sum(1 for t in targets.values()
               if t.get("compiled") and t.get("verdict") == "success")
    print(f"\n{n_ok}/{len(targets)} targets verified; "
          f"{len(errors)} error(s), {len(warnings)} warning(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
