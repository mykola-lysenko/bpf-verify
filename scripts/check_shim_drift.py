#!/usr/bin/env python3
"""Detect drift between functions copied into shims/ and the kernel source.

Several shims are self-contained rewrites that copy the kernel's algorithmic
functions (see shims/kernel/bpf/*.c). The findings documents claim those
copies stay faithful to the kernel implementation; this check keeps that
claim honest as the kernel tree moves.

For every function pair in SHIM_COPIES it extracts the function body from
both the shim and the kernel file, normalizes it (comments stripped,
whitespace collapsed, shim-local renames and inlining attributes undone),
and compares:

  - mode "exact":  normalized bodies must be identical -> error otherwise
  - mode "report": differences are printed as warnings (adapted functions
                   where divergence is expected, e.g. BPF-safe bit ops)

A function missing from the kernel file is always an error (the kernel
renamed or moved it -- the shim and the findings need updating), in either
mode.

Usage:  BPF_KSRC=/path/to/kernel scripts/check_shim_drift.py
"""
import difflib
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).parent.parent
KSRC = Path(os.environ.get("BPF_KSRC",
                           str(Path.home() / "bpf-next-0aa637869")))

# (shim file, kernel file candidates, [(shim fn, kernel fn, mode), ...])
SHIM_COPIES = [
    ("shims/kernel/bpf/lpm_trie.c",
     ["kernel/bpf/lpm_trie.c"],
     [
         ("extract_bit", "extract_bit", "exact"),
         ("longest_prefix_match", "longest_prefix_match", "report"),
         ("trie_lookup_elem", "trie_lookup_elem", "report"),
         ("trie_update_elem", "trie_update_elem", "report"),
         ("trie_delete_elem", "trie_delete_elem", "report"),
     ]),
    ("shims/kernel/bpf/bpf_lru_list.c",
     ["kernel/bpf/bpf_lru_list.c"],
     [
         ("bpf_lru_node_is_ref", "bpf_lru_node_is_ref", "report"),
         ("bpf_lru_list_count_inc", "bpf_lru_list_count_inc", "report"),
         ("bpf_lru_list_count_dec", "bpf_lru_list_count_dec", "report"),
         ("__bpf_lru_node_move_to_free", "__bpf_lru_node_move_to_free", "report"),
         ("__bpf_lru_node_move_in", "__bpf_lru_node_move_in", "report"),
         ("__bpf_lru_node_move", "__bpf_lru_node_move", "report"),
         ("bpf_lru_list_inactive_low", "bpf_lru_list_inactive_low", "report"),
         ("__bpf_lru_list_rotate_active", "__bpf_lru_list_rotate_active", "report"),
         ("__bpf_lru_list_rotate_inactive", "__bpf_lru_list_rotate_inactive", "report"),
         ("__bpf_lru_list_shrink_inactive", "__bpf_lru_list_shrink_inactive", "report"),
         ("__bpf_lru_list_shrink", "__bpf_lru_list_shrink", "report"),
         ("__bpf_lru_list_rotate", "__bpf_lru_list_rotate", "report"),
     ]),
    ("shims/kernel/bpf/bloom_filter.c",
     ["kernel/bpf/bloom_filter.c"],
     [
         # The shim's bit ops are intentionally different (verifier-friendly
         # explicit array indexing); peek/push follow the kernel structure.
         ("bloom_hash", "hash", "report"),
         ("bloom_map_peek_elem", "bloom_map_peek_elem", "report"),
         ("bloom_map_push_elem", "bloom_map_push_elem", "report"),
     ]),
]

FN_ATTRS = re.compile(
    r"__attribute__\(\(always_inline\)\)|__always_inline|\bnoinline\b|"
    r"\bstatic\b|\binline\b")


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    return text


def extract_function(text, name):
    """Return the function definition 'name(...) {...}' or None."""
    clean = strip_comments(text)
    # find a definition: name, argument list, then '{' (not a mere call/proto)
    for m in re.finditer(rf"\b{re.escape(name)}\s*\(", clean):
        i = m.end() - 1
        depth = 0
        while i < len(clean):          # skip the argument list
            if clean[i] == "(":
                depth += 1
            elif clean[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        j = i + 1
        while j < len(clean) and clean[j] in " \t\n":
            j += 1
        if j >= len(clean) or clean[j] != "{":
            continue                   # prototype or call, not a definition
        depth = 0
        k = j
        while k < len(clean):          # capture the body
            if clean[k] == "{":
                depth += 1
            elif clean[k] == "}":
                depth -= 1
                if depth == 0:
                    return name + clean[m.end() - 1:k + 1]
            k += 1
    return None


def normalize(body, rename=None):
    if rename:
        body = re.sub(rf"\b{re.escape(rename[0])}\b", rename[1], body)
    body = FN_ATTRS.sub(" ", body)
    body = re.sub(r"\s+", " ", body).strip()
    # re-split on statement/block boundaries for readable diffs
    body = re.sub(r"([;{}])\s*", r"\1\n", body)
    return body


def main():
    if not KSRC.is_dir():
        print(f"::warning::kernel source not found at {KSRC}; "
              f"set BPF_KSRC. Skipping shim drift check.")
        return 0

    errors = 0
    drift = 0
    for shim_rel, kernel_candidates, functions in SHIM_COPIES:
        shim_text = (REPO / shim_rel).read_text()
        kernel_path = next(
            (KSRC / c for c in kernel_candidates if (KSRC / c).exists()), None)
        if kernel_path is None:
            print(f"::error::{shim_rel}: kernel counterpart not found "
                  f"(tried {kernel_candidates})")
            errors += 1
            continue
        kernel_text = kernel_path.read_text()

        for shim_fn, kernel_fn, mode in functions:
            shim_body = extract_function(shim_text, shim_fn)
            kernel_body = extract_function(kernel_text, kernel_fn)
            if shim_body is None:
                print(f"::error::{shim_rel}: function {shim_fn}() not found in shim")
                errors += 1
                continue
            if kernel_body is None:
                print(f"::error::{kernel_path}: function {kernel_fn}() vanished "
                      f"from the kernel (renamed/moved?); update {shim_rel} "
                      f"and this check")
                errors += 1
                continue
            a = normalize(shim_body, rename=(shim_fn, kernel_fn))
            b = normalize(kernel_body)
            if a == b:
                continue
            diff = "\n".join(difflib.unified_diff(
                b.splitlines(), a.splitlines(),
                f"kernel:{kernel_fn}", f"shim:{shim_fn}", lineterm="", n=1))
            if mode == "exact":
                print(f"::error::{shim_rel}: {shim_fn}() drifted from "
                      f"kernel {kernel_fn}():\n{diff}")
                errors += 1
            else:
                drift += 1
                print(f"::warning::{shim_rel}: {shim_fn}() differs from "
                      f"kernel {kernel_fn}() (adapted copy; review the diff)")
                print(diff)

    print(f"\nshim drift check: {errors} error(s), {drift} adapted function(s) "
          f"with differences")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
