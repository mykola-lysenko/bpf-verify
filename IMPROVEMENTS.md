# Improvement Backlog

Working list of engineering improvements identified during the 2026-07 review.
Work through top to bottom; check items off as they land.

- [x] **1. Split the `pipeline.py` monolith.** ~95% of its 11k lines is C code
  embedded in Python strings. Move each target's harness body, pre-include,
  preamble, and per-target flags into `targets/<name>/` files, leaving
  `pipeline.py` as a small driver. Fixes C syntax highlighting, brace-escaping
  in the template, and unreviewable diffs.
- [x] **2. Fix silent duplicate-key bugs.** *(Resolved structurally by item 1:
  one directory per target, duplicate `targets/ORDER` entries are a hard
  error, and the dead earlier crc16/crc32 harness bodies were dropped —
  the surviving crc16 body is the intended map-seeded rework.)* Python dict literals allow
  duplicate keys and the last silently wins: `HARNESS_BODIES` defines
  `"crc16"` three times and `"crc32"` twice; the `candidates` dict duplicates
  `crc32`/`crc16`. Earlier harness bodies are dead code. Add a uniqueness
  check (structurally fixed by item 1's per-target layout).
- [x] **3. Machine-readable results + checked-in baseline.** *(pipeline.py
  now writes `results.json`; `scripts/check_results.py` gates CI and diffs
  against `baseline/results.json`. Baseline bootstrap: see
  `baseline/README.md` — needs one green CI run to generate real numbers.)* Emit per-target
  JSON (compiled, verified, instructions, states, duration), commit a
  baseline, and have CI diff against it so per-target and instruction-count
  regressions are caught — not just aggregate counts.
- [x] **4. Guard against harness degeneration.** *(Implemented relative to
  the baseline instead of per-target minimums: check_results.py fails when a
  verified program's instruction count drops below 50% of its baseline
  value.)*
- [x] **5. Verify "verbatim" shim claims in CI.** *(scripts/check_shim_drift.py,
  wired into CI. Testing against current bpf-next already shows real drift:
  upstream refactored `longest_prefix_match` into a `__longest_prefix_match`
  wrapper and moved lpm_trie to `bpf_mem_cache` — the shims track the pinned
  snapshot, not tip-of-tree.)* Diff the function bodies
  copied into `shims/` (tnum, lpm_trie, bpf_lru_list, bloom_filter, ...)
  against the kernel tree so shim drift is detected.
- [x] **6. Reproducible environment.** *(setup.sh now fetches the pinned
  bpf-next snapshot from git.kernel.org; results.json records clang and
  kernel versions; checked-in veristat binary removed.)* Replace the personal Google Drive
  kernel tarball with a pinned public git fetch; record the exact LLVM
  snapshot version in results; drop the 2.8MB checked-in `veristat` binary
  (redundant with the uml-veristat submodule).
- [x] **7. Smaller cleanups.**
  - Unused `get_functions()` gone (driver rewrite).
  - The verbose veristat pass is now opt-in (`BPF_VERISTAT_VERBOSE=1`; CI
    sets it to keep the verifier-log artifact); stats come from one CSV run.
  - veristat runs in batches (`BPF_VERISTAT_BATCH`, default 32) with a
    per-batch timeout, so one hanging program no longer kills the whole run.
  - README status updated (156/156, points at the baseline instead of
    hardcoded counts); `findings.md` merged into
    `BPF_Verification_Findings.md` as an appendix; stale
    `test_fixes.py` removed and `test_compile.py` rewritten against the new
    driver.
