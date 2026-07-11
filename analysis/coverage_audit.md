# Coverage audit: hollow `coverage` targets

The `coverage` suite is meant to be the *real* verification tier — each target
carries a custom harness that calls into the kernel function so the verifier
actually walks its instructions. But a harness only covers the function if the
compiler keeps the call live. When the target function is `static`, its result
is unused, or a `BPF_ASSERT` condition is a tautology, clang constant-folds /
dead-strips it and the verified program collapses to `return 0` (~2 insns).
Such a target is `coverage` in name only.

## Signal

Instruction count from `veristat`. A `coverage`-suite target that verifies
`<= 4` insns is **hollow**. `scripts/check_results.py` now emits a non-fatal
`::warning::` listing them on every run, so hollow coverage cannot silently
inflate the "N verified" number. (`compat` targets are *expected* to be
trivial — they only prove the file compiles and loads — so they are excluded.)

This complements the existing `DEGENERATION_RATIO` gate, which catches a target
that *regresses* from non-trivial to trivial; the born-trivial check catches
targets that were never live to begin with.

## Snapshot (bpf-next `77f02c99`, pinned)

19 hollow `coverage` targets (all 2 insns):

```
arc4  ashldi3  ashrdi3  bpf_lsm_proto  crc32  crc7  crc_t10dif  disasm
dynamic_queue_limits  errname  int_log  lcm  list_sort  memweight
mpih_addmul1  mpih_submul1  nh  rational_v2  win_minmax
```

Distribution across the suite (for context):

| Suite | n | trivial (≤4 insns) | median insns |
|-------|---|--------------------|--------------|
| compat | 55 | 55 (by design) | 2 |
| coverage | 117 | 19 (hollow) | 130 |
| proof | 40 | 0 | 105 |

## What to do with them

These are not failures — they compile and verify — but they should be either
**strengthened** (make the harness consume the function's result via
`input_map`-seeded inputs, mark the source helper `noinline`, or assert a real
postcondition, as the CRC / `seq_buf` harnesses already do) or, if the function
genuinely cannot be kept live under the verifier, **reclassified** to `compat`
so the coverage count reflects only targets that actually exercise code.
Strengthening is tracked as follow-up work; the warning keeps the list honest
in the meantime.
