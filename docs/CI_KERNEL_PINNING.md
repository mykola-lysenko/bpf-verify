# CI kernel pinning

The pipeline verifies real kernel code against the in-kernel BPF verifier, so
its results depend on **which bpf-next commit** the targets are compiled and
verified against. `uml-veristat`'s `build.sh` tracks the bpf-next *tip* and
applies a patch stack on top of it, which means an unpinned build drifts every
time bpf-next moves: a target that referenced a now-changed kernel interface
starts failing (e.g. `dispatcher` when `bpf_prog_pack_alloc()` grew a
parameter, or `bpf_inode_storage` when the kernel added `bpf_lsm_initialized`).

Left unmanaged, that makes a red CI ambiguous: did *we* break something, or did
the kernel drift? We split the two signals.

## Two jobs

| Job | Workflow | Trigger | Kernel | Gates? | A failure means |
|-----|----------|---------|--------|--------|-----------------|
| **Pinned** | `bpf-verify.yml` | push / PR | commit in `KERNEL_PIN` | **yes** | we changed something that broke verification |
| **Tracking** | `bpf-verify-tracking.yml` | weekly cron + manual | current tip | no | bpf-next / toolchain drifted — a *finding* |

The pinned job is reproducible: same `KERNEL_PIN` → same kernel → same verdicts.
A red pinned run is always actionable. The tracking job is the early-warning
system; its failures are triaged as findings (same discipline as the toolchain
boundaries in `FINDINGS_EXECUTION.md`) and drive pin bumps.

## How the pin is materialized

`build.sh` clones bpf-next `--branch master --depth=1` and cannot pin an
arbitrary SHA (kernel.org refuses `git fetch <sha>`, and a shallow clone can't
reach an old commit). So the pinned workflow side-steps `build.sh`'s fetch
entirely, with **no submodule change**:

1. Download the pinned commit's source as a kernel.org cgit **snapshot
   tarball** (`.../bpf-next.git/snapshot/bpf-next-<PIN>.tar.gz`).
2. Extract it into `.build/bpf-next` and make it a git repo (`git init` +
   commit) so the patch stack's `git am` works.
3. Run `build.sh` **without `--update`**. Because the fresh repo has no
   `origin/master` ref, `build.sh`'s `UPSTREAM_REF` falls back to `HEAD`, so it
   does **not** reset to the moving tip — it applies the patch stack on top of
   the pinned tree.

`KERNEL_PIN` is part of the build cache key, so bumping it forces a rebuild.

The pin must be a **real bpf-next commit** (the base the patch stack applies
onto), not a commit from inside the patch stack. To read the current base from a
working build: `git -C .build/bpf-next rev-parse origin/master`.

## Bumping the pin

When the tracking job goes green on a newer tip (or after you fix the targets a
tracking failure surfaced):

1. Find the new base commit the tracking build used:
   `git -C deps/.../.build/bpf-next rev-parse origin/master`.
2. Update `KERNEL_PIN` to that SHA.
3. Rebuild locally against it and regenerate the baseline:
   ```bash
   # in deps/bpf-uml-selftests/uml-veristat
   ./build.sh --update --reuse-llvm          # or pin-seed as the workflow does
   # back in the repo root
   python3 pipeline.py
   python3 scripts/check_results.py output2/results.json --update-baseline
   ```
4. Commit `KERNEL_PIN` + `baseline/results.json` together, with a note on which
   targets were adapted for the new kernel.

The submodule bump (a new `uml-veristat` revision, e.g. a refreshed patch stack)
is a separate change; when both move together, do the submodule bump first so
the patch stack matches the newer kernel.
