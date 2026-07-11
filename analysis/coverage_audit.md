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

## Resolution (bpf-next `77f02c99`, pinned)

The initial audit found **19 hollow `coverage` targets** (all 2 insns). All 19
were triaged:

**12 strengthened** — seeded from `input_map` so the call stays live; they now
verify real instruction counts:

```
ashldi3(39)  ashrdi3(47)  crc32(273)  crc7(100)  crc_t10dif(162)
int_log(1369)  dynamic_queue_limits(13)  win_minmax(125)
mpih_addmul1(104)  mpih_submul1(154)  bpf_lsm_proto(18)  errname(185)
```

**7 reclassified to `compat`** — genuinely cannot be kept live under the
verifier / BPF, so they are compile-and-load checks, not coverage:

| Target | Why it can't be live coverage |
|--------|-------------------------------|
| `lcm` | calls `gcd()`'s unbounded `for(;;)` loop — back-edge rejected |
| `memweight` | pointer→integer cast for alignment — rejected on stack pointers |
| `arc4` | 1 KB S-box (`u32 S[256]`) exceeds the 512-byte BPF stack |
| `list_sort` | indirect comparator callback — not valid BPF |
| `nh` | 1088-byte key array exceeds the BPF stack once live |
| `rational_v2` | continued-fraction loop doesn't verify with symbolic inputs (fuzzed in userspace instead) |
| `disasm` | `func_id_name()` bounds-checks the id on a different register than the computed index → the bound doesn't propagate for a symbolic id (verifier precision) |

After this pass the born-trivial check reports **0 hollow coverage targets**;
suite counts are compat 62 / coverage 110 / proof 40. The check stays in
`check_results.py` as a standing guard so newly-added coverage targets can't
silently regress to no-ops.
