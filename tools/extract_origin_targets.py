#!/usr/bin/env python3
"""Project origin's monolithic pipeline target data into targets/<name>/ files.

Imports origin's pipeline.py (its per-target data lives in module-level dicts),
iterates the candidate table, and emits one directory per target in this repo's
targets/ layout. Re-templatizes absolute KSRC/SHIM paths back to {ksrc}/{shim}.

Generates into a staging dir first (argv[1]); a second pass applies to targets/.
"""
import importlib.util, os, sys, json, re, shutil
from pathlib import Path

# One-shot migration record: how targets/<name>/ was projected from the
# upstream monolithic pipeline.py at merge time. To reproduce, first dump the
# upstream file:  git show origin/master:pipeline.py > /tmp/pipeline_origin.py
# then run:       python3 tools/extract_origin_targets.py <stage-dir> [/tmp/pipeline_origin.py]
REPO = Path(__file__).resolve().parent.parent
ORIGIN_PY = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/tmp/origin-study/pipeline_origin.py")
STAGE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/origin-study/targets_gen")

# Real kernel tree so first_existing()/.exists() resolve as origin would.
real_ksrc = subprocess_ksrc = str(
    REPO / "deps/bpf-uml-selftests/uml-veristat/.build/bpf-next")
os.environ["BPF_KSRC"] = real_ksrc
os.environ["BPF_OUTPUT"] = "/tmp/origin-study/out"

spec = importlib.util.spec_from_file_location("porig", str(ORIGIN_PY))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

KSRC = str(m.KSRC)
SHIM = str(m.SHIM)          # origin's shims dir (the /tmp copy) -- for templatizing
DEFAULT = m.DEFAULT_HARNESS_BODY


def templatize(s):
    """Absolute KSRC/SHIM paths -> {ksrc}/{shim} tokens (idempotent)."""
    return s.replace(KSRC, "{ksrc}").replace(SHIM, "{shim}")


# --- Parse the candidates table for src paths (preserving first_existing alts) ---
src_text = ORIGIN_PY.read_text()
block = re.search(r"\n    candidates = \{(.*?)\n    \}", src_text, re.S).group(1)

REPO_SHIM = str(REPO / "shims")
order = []            # names in historical source order (first occurrence)
cand_paths = {}       # name -> [templated src candidate paths] (last wins, like dict)
for line in block.splitlines():
    mm = re.match(r'\s*"([^"]+)":\s*(.+)', line)
    if not mm:
        continue
    name, expr = mm.group(1), mm.group(2)
    # Sources come from KSRC (kernel tree) or SHIM (a shimmed copy under shims/).
    parts = re.findall(r'(KSRC|SHIM)\s*/\s*"([^"]+)"', expr)
    if not parts:
        print("  WARN: no KSRC/SHIM path parsed for", name, "->", expr.strip())
        continue
    if name not in cand_paths:
        order.append(name)
    cand_paths[name] = [("{ksrc}/" + p) if base == "KSRC" else ("{shim}/" + p)
                        for base, p in parts]


def real_path(templated):
    return templated.replace("{ksrc}", KSRC).replace("{shim}", REPO_SHIM)

# --- Emit one target dir per candidate ---
if STAGE.exists():
    shutil.rmtree(STAGE)
STAGE.mkdir(parents=True)

exists_order = []
counts = {"compat": 0, "coverage": 0, "proof": 0}
n_harness = n_pre = n_pre_shared = n_preamble = 0
for name in order:
    tdir = STAGE / name
    tdir.mkdir()
    cfg = {"src": cand_paths[name]}

    body = m.HARNESS_BODIES.get(name, DEFAULT)
    has_custom = name in m.HARNESS_BODIES
    suite, _kind = m.classify_target(name, has_custom, body)
    cfg["suite"] = suite
    counts[suite] += 1

    # harness.c only when a real (non-default) custom body exists
    if has_custom and body != DEFAULT:
        (tdir / "harness.c").write_text(body if body.endswith("\n") else body + "\n")
        n_harness += 1

    pre = m.EXTRA_PRE_INCLUDE.get(name)
    if pre:
        (tdir / "pre_include.h").write_text(templatize(pre))
        n_pre += 1

    preamble = m.EXTRA_PREAMBLE.get(name)
    if preamble:
        (tdir / "preamble.h").write_text(templatize(preamble))
        n_preamble += 1

    incs = m.EXTRA_INCLUDES.get(name)
    if callable(incs):
        incs = incs()
    if incs:
        cfg["extra_includes"] = [[templatize(str(p))] for p in incs]

    cf = m.EXTRA_CFLAGS.get(name)
    if cf:
        cfg["extra_cflags"] = [templatize(str(x)) for x in cf]

    ecf = m.EXTRA_EARLY_CFLAGS.get(name)
    if ecf:
        cfg["extra_early_cflags"] = [templatize(str(x)) for x in ecf]

    (tdir / "target.json").write_text(json.dumps(cfg, indent=2) + "\n")

    # does any src candidate resolve on this kernel / shim tree?
    if any(Path(real_path(c)).exists() for c in cand_paths[name]):
        exists_order.append(name)

# ORDER: only targets whose source exists on this kernel (matches origin's 214)
(STAGE / "ORDER").write_text("\n".join(exists_order) + "\n")

print(f"candidates parsed: {len(order)}  | src exists: {len(exists_order)}")
print(f"suites (all candidates): {counts}")
print(f"files: harness.c={n_harness} pre_include={n_pre} preamble={n_preamble}")
missing_src = [n for n in order if n not in exists_order]
print(f"missing-source (excluded from ORDER): {missing_src}")
