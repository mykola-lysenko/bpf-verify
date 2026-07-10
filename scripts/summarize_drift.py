#!/usr/bin/env python3
"""Summarize a tracking-run results.json: which targets failed against tip.

Used by the tracking CI job to render a drift summary. Prints Markdown to
stdout (appended to the job summary). Exits 0 regardless -- the tracking job is
non-gating; this only reports.
"""
import json
import sys
from pathlib import Path


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("output/results.json")
    if not path.exists():
        print("No results.json (pipeline did not produce results).")
        return
    targets = json.loads(path.read_text()).get("targets", {})
    compile_fail = [n for n, e in targets.items() if not e.get("compiled")]
    verify_fail = [
        (n, e.get("verdict")) for n, e in targets.items()
        if e.get("compiled") and e.get("verdict") not in (None, "success")
    ]
    if compile_fail:
        print("### Targets that failed to compile against tip")
        for n in compile_fail:
            print(f"- {n}")
    if verify_fail:
        print("### Targets that failed verification against tip")
        for n, v in verify_fail:
            print(f"- {n}: {v}")
    if not compile_fail and not verify_fail:
        print("No drift: all targets compile and verify against the current tip.")


if __name__ == "__main__":
    main()
