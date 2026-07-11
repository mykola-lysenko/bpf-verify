# Roadmap

The living plan. Pick the highest-priority open item each session instead of
re-deriving priorities. Update it as items land. Companion docs:
`analysis/curation.md` (ranked target worklist), `analysis/coverage_audit.md`
(coverage integrity), `docs/CI_KERNEL_PINNING.md` (CI mechanics),
`FINDINGS_EXECUTION.md` / `BPF_Verification_Findings.md` (results).

## North star

Compile real Linux kernel code to BPF and run it through the in-kernel verifier,
complemented by native-vs-BPF differential testing and host sanitizer fuzzing of
the *same* sources — to (1) characterize what the verifier can and cannot prove
about real kernel code, and (2) find a real, reportable defect. Every direction
below is ranked by **bug expected-value**, not activity.

## Where we are (2026-07)

- 212 verifier targets: compat 62 / coverage 110 / proof 40; coverage is now all
  real (born-trivial guard in `check_results.py`).
- Legs: verifier pipeline, differential (9 targets), userspace ASan/UBSan +
  property + `tnum` soundness (10 harnesses), curation scanner.
- CI: reproducible **pinned** gate (bpf-next pinned via kernel.org snapshot
  tarball) + non-gating **tracking** job that flags drift; pin at `520d7d794`.
- No reportable bug yet. The recurring, real result is a catalog of *toolchain
  boundaries* (stack, unbounded loops, pointer casts, indirect calls, aggregate
  returns, verifier precision) and *threat-model discipline* (the unlzma
  non-bug). Every mainline target — even brand-new crypto — verifies clean.

## Workstreams, by bug-EV

### 1. Verifier soundness — the crown jewel (HIGHEST EV)

A violation here is a **CVE-class verifier bug**: the verifier concluding a
register cannot hold a value it actually can. This is the most novel and
defensible thing the project does, and it is under-invested relative to its EV.

- **`cnum` soundness — DONE (sound, no violation).**
  `userspace/harnesses/cnum_soundness.c` checks the brand-new (2026) circular
  domain (`add`/`negate`/`intersect`/`is_subset`/`contains`/`umin..smax`, 32- &
  64-bit) over small arcs; 1M iters clean, detector validated (planted `add`
  shrink caught at iter 0). See `FINDINGS_EXECUTION.md`. Next on this thread:
  extend beyond the small-arc regime, and add the remaining cnum ops
  (`from_srange` corner cases, `cnum32_from_cnum64`, the mixed 32/64 helpers).
- Extend `tnum_soundness` beyond the ≤6-unknown-bit regime (structured/large
  tnums; targeted adversarial pairs).
- Cross-domain: check `tnum`↔`cnum` consistency where the verifier uses both.
- Expand the `proof` suite: more `BPF_PROVE` invariants over liveness, states,
  backtrack, range_tree — the guard/invariant helpers.

### 2. Untrusted-input parsers — threat-model-appropriate (HIGH EV)

Fuzz code that *claims* to be safe against malicious input but is less-travelled
than the OSS-Fuzz-covered functions. Discipline (the unlzma lesson): only target
code with a real safety contract for untrusted input; triage every OOB against
that contract before reporting.

- Mine `analysis/curation.md` userspace/hostile legs for parsers/decoders with
  an untrusted-input contract (DER/BER already done; look at other TLV/protocol/
  filesystem/keyring parsers). Skip trusted-input decompressors.
- Prefer encode/decode and parse/format *pairs* (round-trip oracle) over
  memory-safety-only, where a contract exists.
- Keep harnesses cheap to add (the `.sources`/`.prebuild`/`khost.h` machinery is
  mature).

### 3. Differential breadth — cheap, continuous (LOW EV, keep running)

BPF-backend miscompilation of real kernel code is rare but high-impact and cheap
to test. Sweet spot: small multiply/rotate/shift primitives whose whole TU fits
the BPF stack (siphash/hsiphash/xxh32/CRCs done). Whole crypto cores are
stack-hostile (curve25519, AES) — userspace-only.

- Add a few per session from the differential worklist; wire the diff leg into
  CI so it runs continuously (currently local-only).

### 5. Compiler-correctness & coverage breadth (deliberately benign; current focus)

Grow the corpus of real kernel code that reaches the LLVM BPF backend and the
verifier. This is toolchain/coverage work: it exposes **BPF-backend
miscompilations, ICEs, and backend limitations** (compiler-correctness), not
attacker-relevant defects — the right thread when we want to steer clear of the
security-adjacent framing. A probe found the bottleneck is **shim completeness**,
not BPF limits: of untargeted `lib/` candidate files, ~5/6 fail to compile only
because our shim tree lacks kernel infrastructure types (`freeptr_t`,
`ARCH_KMALLOC_MINALIGN`, `pgprot_t`, `irq_work`, `completion`, …).

- **Shim completeness (force multiplier, cross-cutting).** Add the missing
  types/macros; each unlock cascades to many files and helps *every* leg
  (coverage, differential, userspace, proof). Re-probe the buildable/total ratio
  after each batch to measure progress.
- **Differential breadth** (Workstream 3) rides the newly-buildable files — the
  sharpest miscompilation detector; prioritize codegen-diverse ops.
- **Coverage breadth.** Map-seeded harnesses for buildable functions that can't
  fold to a scalar, so the verifier walks real code.
- **Widen the scanner** to more roots (`crypto/`, `kernel/`, more of `lib/`).
- **Characterize true boundaries:** split "won't build" into shim-gap (fixable),
  infra-that-can't-be-BPF (irq_work/completion), and real LLVM BPF-backend limits
  (aggregate returns, >5 stack args, signed div, CTTZ) — the last a clean set of
  benign compiler-completeness findings for LLVM/BPF maintainers.
- **Scale the mechanics:** a small harness generator for the common
  "scalar in → scalar out" case to add many targets per session.
- **Be precise with `always_inline`; enable global functions.** See
  `analysis/global_functions_and_inlining.md`. `always_inline` on a *target
  kernel function* is a workaround for global functions being disabled here (the
  pipeline strips `.BTF.ext`, degrading every non-static fn to a static
  subprogram) — use it only when the function truly needs it (returns a
  caller-stack pointer or end-pointer bounds). The **>5-args** case is no longer
  a hard reason: verified that clang 23 + kernel `520d7d794` verify a 6-param
  static subprogram with `.BTF.ext` kept (fail with it stripped). The real win is
  **keeping `.BTF.ext`** (solve the ctx-type lookup): it enables BOTH global
  functions AND >5-arg static subprograms, then route scalar / typed-pointer
  kernel functions through independent (all-inputs) global-function verification.
  Measured global-fn limits: scalars verify; unsized pointers are rejected
  (`mem_or_null`); the `void*,u32 __sz` convention is fragile in our BTF setup;
  real kernel `ptr+end` / un-annotated-`len` signatures don't fit. Needs clang
  23+ (our pinned 22.1.8 rejects >5-arg static subprograms at compile).

Metrics: coverage-target count, differential-target count, buildable/total file
ratio, documented backend boundaries.

### 4. Coverage & harness quality (integrity, not bug-EV)

- Strengthen remaining thin coverage; keep the born-trivial guard green.
- The 7 reclassified boundaries are a catalog of *why* real code resists BPF —
  keep it curated; each is a small characterization finding.

## Operating rhythm (so we don't re-plan the mechanics)

- **Pin bumps.** The weekly tracking job builds against tip. When it is green,
  bump `KERNEL_PIN` per `docs/CI_KERNEL_PINNING.md` (rebuild, verify 212/212,
  regenerate baseline, commit pin+baseline+any drift fixes together). When it is
  red, the failing targets are *findings*: triage as drift-adaptation (like the
  `dispatcher`/`bpf_inode_storage`/`cpumask` fixes) or a new boundary.
- **Push hygiene.** `master` has `cancel-in-progress`; don't push over an
  in-flight pinned build you care about. Baseline changes ride with the change
  that caused them.
- **Toolchain.** Refresh the uml-veristat submodule when its patch stack moves
  (bump the gitlink; the pinned cache key includes `build.sh`/`patches`).

## Explicit non-goals / discipline

- **Do not reimplement fuzzers.** Stay within compile-to-BPF / UML-verify /
  differential / host-shim-of-real-source. The value is running *real kernel
  code* through these oracles.
- **Match the fuzzer's input model to the target's threat model** before
  reporting any OOB (the unlzma triage).
- **No silent hollow coverage** — a target that verifies a no-op is not coverage.
- Validate every detector by planting a bug before trusting a clean run.

## Immediate next pick

**Workstream 5: shim completeness.** The force-multiplier for coverage breadth
and every other leg. Add the missing kernel infrastructure types the buildability
probe surfaced, re-probe, and ride the newly-unlocked files into differential /
coverage targets. (Soundness legs — `tnum`/`cnum` beyond the small regime — and
Workstream 2 remain queued for when we return to them; shim completeness helps
those too.)
