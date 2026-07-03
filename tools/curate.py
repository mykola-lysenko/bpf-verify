#!/usr/bin/env python3
"""Curation scanner: rank kernel functions as bpf-verify targets.

Statically extracts signals from kernel C sources and routes each function to
the bug-finding leg it fits, scoring for bug expected-value. Turns target
curation from hand-picking into a reproducible ranked worklist.

Legs (see the repo README / FINDINGS_EXECUTION.md):
  - differential   native-vs-BPF (any deterministic pure fn that verifies)
  - property       in-kernel execution with a round-trip/invariant oracle
  - userspace      host ASan/UBSan (parsers/decoders; also the fallback for
                   verifier-hostile code)
  - hostile        struct-return / >5 args / recursion / unbounded loop /
                   128-bit / asm / float / signed div -> won't verify or
                   compile to BPF; userspace-only

Usage:
  tools/curate.py [--ksrc DIR] [--roots lib lib/math ...] [--out FILE] [--top N]

Heuristic and regex-based by design (matches the project's pragmatic style); it
ranks candidates for a human to pick, it does not decide. Verify/compile is left
to the pipeline.
"""
import argparse
import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Include classification: deep includes = expensive to shim / deep dep chains.
# ---------------------------------------------------------------------------
DEEP_INCLUDES = re.compile(
    r"<(linux/bpf|linux/sched|linux/mm|linux/mm_types|linux/skbuff|linux/slab|"
    r"linux/percpu|linux/spinlock|linux/rcu|linux/dcache|linux/fs|net/|"
    r"linux/dma|linux/device|linux/netdevice|linux/pagemap|linux/vmalloc|"
    r"linux/interrupt|linux/workqueue|linux/cpumask|linux/atomic|"
    r"linux/blk|linux/scatterlist|linux/highmem|asm/word-at-a-time)")

# codegen-interest keyword classes (weak signals for differential priority)
CODEGEN = {
    "shift":    re.compile(r"<<|>>"),
    "divide":   re.compile(r"[^/*]/[^/*]|%[^=]"),
    "multiply": re.compile(r"\bmul\w*|\*\s*\w|GOLDEN_RATIO|__multi"),
    "byteswap": re.compile(r"swab|bswap|cpu_to_|_to_cpu|be16|be32|be64|le16|le32|le64"),
    "bitcount": re.compile(r"hweight|\bfls\b|fls64|\bffs\b|__ffs|clz|ctz|popcount"),
    "table":    re.compile(r"_table\[|\btable\b|\[[a-z_]\w* *[>&]"),
}

# Pairs that suggest an encode/decode round-trip in the same file.
PAIR_HINTS = [
    ("encode", "decode"), ("compress", "decompress"), ("pack", "unpack"),
    ("2hex", "2bin"), ("bin2", "hex2"), ("_to_", "_from_"),
    ("parse", "format"), ("marshal", "unmarshal"), ("escape", "unescape"),
    ("deflate", "inflate"), ("pton", "ntop"),
]

# Directories/files scanned for test/kunit/fuzz coverage. Kept narrow so the
# scan stays fast; the goal is a novelty signal, not exhaustive coverage.
TEST_ROOTS = ["lib/tests", "lib", "crypto", "kernel/bpf",
              "tools/testing/selftests/bpf/progs"]


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    return text


def split_args(s):
    parts, depth, cur = [], 0, ""
    for c in s:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            parts.append(cur.strip()); cur = ""
        else:
            cur += c
    if cur.strip():
        parts.append(cur.strip())
    return parts


# A definition header: return type (may span tokens/pointers) + name + (args) + {
DEF_RE = re.compile(
    r"(?m)^((?:[A-Za-z_]\w*[ \t\*]+)+?)([A-Za-z_]\w*)[ \t]*\(")


def extract_functions(text):
    """Yield (name, ret_type, args_str, body) for top-level definitions."""
    clean = strip_comments(text)
    for m in DEF_RE.finditer(clean):
        ret, name = m.group(1).strip(), m.group(2)
        if name in ("if", "for", "while", "switch", "return", "sizeof", "defined"):
            continue
        # match the argument parenthesis
        i = m.end() - 1
        depth, j = 0, i
        while j < len(clean):
            if clean[j] == "(":
                depth += 1
            elif clean[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        args = clean[i + 1:j]
        k = j + 1
        while k < len(clean) and clean[k] in " \t\n":
            k += 1
        if k >= len(clean) or clean[k] != "{":
            continue  # prototype, not a definition
        depth, e = 0, k
        while e < len(clean):
            if clean[e] == "{":
                depth += 1
            elif clean[e] == "}":
                depth -= 1
                if depth == 0:
                    break
            e += 1
        yield name, ret, args, clean[k:e + 1]


def analyze(name, ret, args, body, includes):
    arglist = [a for a in split_args(args) if a and a != "void"]
    n_args = len(arglist)
    struct_ret = "struct" in ret and "*" not in ret
    struct_arg = any("struct" in a and "*" not in a for a in arglist)
    variadic = "..." in args
    void_ret = re.match(r"^(static\s+|inline\s+|__\w+\s+)*void\s*$", ret) is not None \
        and "*" not in ret
    recursion = re.search(rf"\b{re.escape(name)}\s*\(", body[body.find("{") + 1:]) is not None
    unbounded = bool(re.search(r"for\s*\(\s*;\s*;\s*\)|while\s*\(\s*1\s*\)|"
                               r"while\s*\(\s*true\s*\)", body))
    int128 = "__int128" in body or "int128" in ret
    has_asm = bool(re.search(r"\basm\b|__asm__", body))
    has_float = bool(re.search(r"\b(float|double)\b", ret + " " + args))
    ptr_len = any("*" in a for a in arglist) and \
        any(re.search(r"\b(len|size|count|n|nbytes|bytes)\b", a) for a in arglist)
    signed = bool(re.search(r"\b(s8|s16|s32|s64|int|long|ssize_t)\b", ret)) and \
        bool(CODEGEN["divide"].search(body))

    codegen = [k for k, rx in CODEGEN.items() if rx.search(body)]
    deep = sum(1 for inc in includes if DEEP_INCLUDES.search(inc))

    hostile = (struct_ret or struct_arg or variadic or n_args > 5 or int128
               or has_asm or has_float or unbounded or recursion or signed)

    return {
        "name": name, "ret": ret.strip(), "n_args": n_args,
        "struct_ret": struct_ret, "variadic": variadic, "void_ret": void_ret,
        "recursion": recursion, "unbounded": unbounded, "int128": int128,
        "asm": has_asm, "float": has_float, "ptr_len": ptr_len, "signed_div": signed,
        "codegen": codegen, "deep_includes": deep, "hostile": hostile,
    }


def hostile_reason(a):
    for flag, why in [
        ("struct_ret", "returns struct by value"), ("variadic", "variadic"),
        ("int128", "128-bit int"), ("asm", "inline asm"), ("float", "floating point"),
        ("unbounded", "unbounded loop"), ("recursion", "recursion"),
        ("signed_div", "signed division"),
    ]:
        if a.get(flag):
            return why
    if a["n_args"] > 5:
        return f"{a['n_args']} args (>5)"
    return ""


def build_tested_names(ksrc):
    """Set of identifier tokens appearing in test/kunit/fuzz sources -- a fast
    membership check for 'does this function look already tested?'."""
    tokens = set()
    tok_re = re.compile(r"[A-Za-z_]\w+")
    for root in TEST_ROOTS:
        base = ksrc / root
        if not base.is_dir():
            continue
        for p in base.rglob("*.c"):
            if not any(t in p.name for t in ("test", "kunit", "fuzz")) \
                    and "selftests" not in str(p):
                continue
            try:
                tokens.update(tok_re.findall(p.read_text(errors="replace")))
            except OSError:
                pass
    return tokens


def load_existing(repo):
    """Function/file tokens already covered by targets/ and diff/."""
    covered = set()
    order = repo / "targets" / "ORDER"
    if order.exists():
        for line in order.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                covered.add(line)
    for d in (repo / "diff").glob("*/compute.h"):
        covered.add(d.parent.name)
        # function names called in compute.h
        for m in re.finditer(r"\b([a-z_]\w+)\s*\(", d.read_text()):
            covered.add(m.group(1))
    return covered


def main():
    repo = Path(__file__).parent.parent
    ap = argparse.ArgumentParser()
    ap.add_argument("--ksrc", type=Path,
                    default=Path(os.environ.get(
                        "BPF_KSRC",
                        repo / "deps/bpf-uml-selftests/uml-veristat/.build/bpf-next")))
    ap.add_argument("--roots", nargs="+",
                    default=["lib", "lib/math", "lib/crc", "lib/crypto"])
    ap.add_argument("--out", type=Path, default=repo / "analysis" / "curation.md")
    ap.add_argument("--top", type=int, default=40)
    args = ap.parse_args()

    if not args.ksrc.is_dir():
        sys.exit(f"kernel source not found: {args.ksrc} (set --ksrc or BPF_KSRC)")

    tested_names = build_tested_names(args.ksrc)
    covered = load_existing(repo)

    rows = []
    for root in args.roots:
        d = args.ksrc / root
        if not d.is_dir():
            continue
        for cf in sorted(d.glob("*.c")):
            try:
                text = cf.read_text(errors="replace")
            except OSError:
                continue
            includes = re.findall(r"#include\s+(<[^>]+>|\"[^\"]+\")", text)
            if any(t in cf.name for t in ("test", "kunit", "fuzz")):
                continue  # don't propose test scaffolding as targets
            fns = list(extract_functions(text))
            names = {n for n, *_ in fns}
            # A round-trip pair needs the two partners as DISTINCT function
            # names (avoid "compress" matching inside "decompress").
            file_pairs = [
                (x, y) for (x, y) in PAIR_HINTS
                if any(x in n and y not in n for n in names)
                and any(y in n and x not in n for n in names)]
            for name, ret, argstr, body in fns:
                if name.startswith("__") and not name.startswith("__bpf"):
                    pass  # keep; internal helpers can still be interesting
                a = analyze(name, ret, argstr, body, includes)
                if a["void_ret"] and not a["ptr_len"]:
                    continue  # void, non-buffer: little to observe
                tested = name in tested_names
                is_covered = name in covered or cf.stem in covered
                # leg routing. A non-hostile function is differential-ready
                # (no oracle needed); if its file also has a round-trip pair it
                # is additionally listed as a property candidate (different bug
                # class). Hostile code is userspace-only: buffer parsers go to
                # the ASan list, the rest to the hostile list.
                legs = []
                if not a["hostile"] and not a["void_ret"]:
                    legs.append("differential")
                    if file_pairs:
                        legs.append("property")
                if a["hostile"]:
                    legs.append("userspace" if a["ptr_len"] else "hostile")
                elif a["ptr_len"] and not legs:
                    legs.append("userspace")
                if not legs:
                    continue
                # bug-EV score
                score = 0
                score += 3 if not tested else 0
                score += 2 - min(a["deep_includes"], 2)
                score += len(a["codegen"])
                score += 1 if a["ptr_len"] else 0
                score += 1 if "differential" in legs else 0
                score -= 5 if is_covered else 0
                rows.append({
                    **a, "file": f"{root}/{cf.name}", "tested": tested,
                    "covered": is_covered, "legs": legs, "pairs": file_pairs,
                    "score": score,
                })

    # ---- emit ranked worklist ----
    args.out.parent.mkdir(parents=True, exist_ok=True)
    by_leg = {}
    for r in rows:
        for leg in r["legs"]:
            by_leg.setdefault(leg, []).append(r)
    for v in by_leg.values():
        v.sort(key=lambda r: (-r["score"], r["file"], r["name"]))

    lines = ["# Curation worklist",
             "",
             f"Auto-generated by `tools/curate.py` from `{args.ksrc.name}`.",
             f"Roots: {', '.join(args.roots)}. "
             f"{len(rows)} candidate functions; "
             f"{sum(1 for r in rows if not r['covered'])} not yet covered.",
             "",
             "Score = untested(+3) + shim-ease(0..2) + codegen-classes + "
             "buffer(+1) + differential(+1) − already-covered(−5). "
             "Heuristic ranking for a human to pick; the pipeline decides "
             "verify/compile.",
             ""]

    leg_titles = {
        "differential": "Differential candidates (native-vs-BPF; no oracle needed)",
        "property": "Property candidates (round-trip pair in same file)",
        "userspace": "Userspace-ASan candidates (buffer parsers/decoders)",
        "hostile": "Verifier-hostile (userspace-only; won't verify/compile to BPF)",
    }
    for leg in ("differential", "property", "userspace", "hostile"):
        items = [r for r in by_leg.get(leg, []) if not r["covered"]]
        lines += [f"## {leg_titles[leg]}", ""]
        if not items:
            lines += ["_none_", ""]
            continue
        lines.append("| Score | Function | File | Args | Codegen | Untested | Notes |")
        lines.append("|------:|----------|------|-----:|---------|:--------:|-------|")
        for r in items[:args.top]:
            notes = []
            if leg == "hostile":
                notes.append(hostile_reason(r))
            if r["pairs"]:
                notes.append("pair:" + "/".join(f"{x}+{y}" for x, y in r["pairs"]))
            if r["deep_includes"]:
                notes.append(f"{r['deep_includes']} deep-inc")
            lines.append(
                f"| {r['score']} | `{r['name']}` | {r['file']} | {r['n_args']} | "
                f"{','.join(r['codegen']) or '-'} | {'yes' if not r['tested'] else ''} | "
                f"{'; '.join(n for n in notes if n)} |")
        lines.append("")

    args.out.write_text("\n".join(lines) + "\n")
    print(f"wrote {args.out}")
    for leg in ("differential", "property", "userspace", "hostile"):
        n = sum(1 for r in by_leg.get(leg, []) if not r["covered"])
        print(f"  {leg:12s}: {n} new candidates")


if __name__ == "__main__":
    main()
