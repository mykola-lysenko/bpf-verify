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

- **`cnum` soundness (do first).** `cnum` is the brand-new (2026) signed-range
  abstract domain — far less battle-tested than `tnum`. Build a `cnum_soundness`
  harness mirroring `userspace/harnesses/tnum_soundness.c`: for random small
  `cnum`s, enumerate γ(a), γ(b) exhaustively and check every concrete `OP(x,y)`
  is contained in `cnum_OP(a,b)` for all ops. Validate the detector by planting
  an unsound op. **This is the single highest-probability place to find a real
  bug right now.**
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

**Workstream 1: build `cnum_soundness`.** New 2026 domain, exhaustive-enumeration
oracle already proven for `tnum`, highest bug-probability per hour.
