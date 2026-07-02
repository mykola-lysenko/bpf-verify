#!/usr/bin/env python3
"""
BPF Kernel Verification Pipeline
Compiles Linux kernel lib/ source files to BPF bytecode and verifies them
with the in-kernel BPF verifier via veristat.

Per-target configuration lives in targets/<name>/:
  target.json     source-path candidates, extra cflags, extra includes,
                  shared pre-include references
  harness.c       harness body inserted into the BPF program entry point
                  (defaults to "return 0;" if absent)
  pre_include.h   C text injected BEFORE the kernel source include
  preamble.h      C text injected AFTER the kernel source include

targets/harness_template.c is the harness skeleton (@TOKEN@ placeholders),
targets/ORDER is the build/verification order, and targets/_shared/ holds
pre-include snippets shared by several targets. The strings {ksrc} and
{shim} in target.json and pre_include.h are replaced with the kernel-source
and shims/ paths at build time.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

# All paths are overridable via environment variables so the pipeline runs
# on any host (local sandbox, GitHub Actions runner, etc.).
_HOME = Path(os.environ.get("HOME", "/home/ubuntu"))
KSRC = Path(os.environ.get("BPF_KSRC", str(_HOME / "bpf-next-0aa637869")))
SHIM = Path(__file__).parent / "shims"
OUTPUT = Path(os.environ.get("BPF_OUTPUT", str(Path(__file__).parent / "output2")))
VERISTAT = os.environ.get("BPF_VERISTAT", str(
    Path(__file__).parent / "deps" / "bpf-uml-selftests" / "uml-veristat" / "uml-veristat"
))
CLANG = os.environ.get("BPF_CLANG", "/usr/bin/clang-23")
LLVM_OBJCOPY = os.environ.get("BPF_LLVM_OBJCOPY", "/usr/bin/llvm-objcopy-23")
TARGETS_DIR = Path(__file__).parent / "targets"

OUTPUT.mkdir(parents=True, exist_ok=True)

# Common BPF compile flags
BPF_CFLAGS = [
    CLANG,
    "-target", "bpf",
    "-O2",
    "-g",   # Required for pahole to generate BTF debug info
    "-nostdinc",
    "-isystem", "/usr/lib/llvm-23/lib/clang/23/include",
    # shims/ mirrors the kernel tree layout: shims/include/linux/ shadows include/linux/,
    # shims/arch/x86/include/asm/ shadows arch/x86/include/asm/, etc.
    # A single -I{SHIM} is sufficient because each shim lives at the same
    # sub-path as its kernel counterpart.
    f"-I{SHIM}", f"-I{SHIM}/include", f"-I{SHIM}/arch/x86/include",
    f"-I{KSRC}", f"-I{KSRC}/include",
    f"-I{KSRC}/include/uapi",
    f"-I{KSRC}/include/generated/uapi",
    f"-I{KSRC}/arch/x86/include",
    f"-I{KSRC}/arch/x86/include/uapi",
    f"-I{KSRC}/arch/x86/include/generated",
    f"-I{KSRC}/arch/x86/include/generated/uapi",
    "-include", f"{KSRC}/include/linux/compiler-version.h",
    "-include", f"{KSRC}/include/linux/kconfig.h",
    f"-I{KSRC}/ubuntu/include",
    "-include", f"{KSRC}/include/linux/compiler_types.h",
    "-D__KERNEL__",
    # --- Layer 1: Real kernel CONFIG_* symbols ---
    # Generated from /proc/config.gz of the running kernel (6.1.102) via
    # config_to_autoconf.py and installed as include/generated/autoconf.h in
    # the source tree. kconfig.h (force-included above) does
    # '#include <generated/autoconf.h>' which picks it up automatically.
    # This replaces all manual -DCONFIG_* flags with the minimal configuration
    # needed by this standalone build. Values that generated headers validate
    # directly, such as CONFIG_HZ, must match the checked-out kernel tree.
    # Override a few CONFIG symbols that conflict with BPF compilation:
    # CONFIG_UPROBES pulls in arch_uprobe_task which is not in our shim.
    "-UCONFIG_UPROBES",
    # CONFIG_NUMA pulls in asm/sparsemem.h (not in our shim) and linux/printk.h.
    "-UCONFIG_NUMA",
    # Block linux/module.h -- it pulls in linux/sched.h and the full
    # task scheduler type system, which is too deep to shim.
    "-D_LINUX_MODULE_H",
    # Block linux/export.h -- it redefines EXPORT_SYMBOL with a complex asm
    # block that generates non-BPF ELF sections.
    "-D_LINUX_EXPORT_H",
    # Block linux/panic.h and linux/printk.h -- their function declarations
    # conflict with our no-op macro definitions in the harness template.
    "-D__KERNEL_PRINTK__",
    "-D_LINUX_PANIC_H",
    # Block linux/sprintf.h -- our harness defines snprintf as a macro which
    # conflicts with sprintf.h's function declarations.
    "-D_LINUX_KERNEL_SPRINTF_H_",
    # Block linux/random.h -- our harness defines get_random_bytes with a
    # different signature (int nbytes vs size_t len), causing a conflict.
    "-D_LINUX_RANDOM_H",
    # Suppress likely/unlikely as compiler-level macros so they don't
    # generate extern BTF references (win_minmax and others use them).
    "-Dunlikely(x)=(x)",
    "-Dlikely(x)=(x)",
    # __read_mostly is defined in linux/cache.h, but many headers (e.g. rcupdate.h)
    # don't include cache.h. Define it as empty globally.
    "-D__read_mostly=",
    "-D____cacheline_aligned=__attribute__((__aligned__(64)))",
    "-D____cacheline_aligned_in_smp=__attribute__((__aligned__(64)))",
    # Block headers replaced by -D guards + harness stubs (strategy 3)
    "-D_ASM_X86_KFENCE_H",
    "-D_ASM_X86_TIMEX_H",
    "-D_LINUX_FORTIFY_STRING_H_",
    "-D_LINUX_BH_H",
    "-D_LINUX_IRQFLAGS_H",
    # THIS_MODULE is defined in linux/module.h which we block with -D_LINUX_MODULE_H.
    "-DTHIS_MODULE=NULL",
    # Block linux/kprobes.h -- it pulls in ftrace.h -> trace_recursion.h ->
    # interrupt.h -> hardirq.h -> sched.h which requires arch-specific symbols.
    "-D_LINUX_KPROBES_H",
    "-DNOKPROBE_SYMBOL(x)=",
    # Block linux/pgtable.h -- it uses pud_pgtable/pmd_offset which require
    # full MM infrastructure incompatible with BPF compilation.
    "-D_LINUX_PGTABLE_H",
    # Precompute KTIME_SEC_MAX to avoid sdiv instruction in ktime.h/time64.h.
    "-DKTIME_SEC_MAX=9223372036LL",
    "-DKTIME_SEC_MIN=(-9223372037LL)",
    # Precompute THREAD_SIZE for sched.h (used in init_stack array size).
    # x86_64: PAGE_SIZE=4096, THREAD_SIZE_ORDER=2, KASAN_STACK_ORDER=0.
    "-DTHREAD_SIZE=16384UL",
    # COMPILE_OFFSETS: skip sched.h's __migrate_enable/__migrate_disable section
    # which uses RQ_nr_pinned (a generated constant from asm-offsets.h not in our tree).
    # With COMPILE_OFFSETS defined, sched.h provides empty stubs for these functions
    # and skips the include of generated/rq-offsets.h (which is empty anyway).
    "-DCOMPILE_OFFSETS",
    # TIF_NOTIFY_RESUME is defined in asm/thread_info.h (x86_64: value=1).
    "-DTIF_NOTIFY_RESUME=1",
    # __latent_entropy is a GCC plugin attribute that Clang doesn't support.
    "-D__latent_entropy=",
    # CONFIG_CPU_NO_EFFICIENT_FFS: BPF backend doesn't support CTTZ (opcode 191).
    # This makes gcd.c, lcm.c, find_bit.c etc. use loop-based bit scanning
    # instead of __ffs/__fls which expand to __builtin_ctzl/__builtin_clzl.
    "-DCONFIG_CPU_NO_EFFICIENT_FFS",
    # __init/__exit/__initconst/__initdata expand to __section(".init.*") attributes
    # that the BPF backend doesn't support.
    "-D__init=", "-D__exit=", "-D__initconst=", "-D__initdata=",
    # Prevent the compiler from converting memcpy/memset/memmove/memcmp/strlen/strcpy
    # calls to their __builtin_* equivalents, which the BPF backend rejects.
    "-fno-builtin-memset", "-fno-builtin-memmove", "-fno-builtin-memcpy",
    "-fno-builtin-memcmp", "-fno-builtin-strlen", "-fno-builtin-strcpy",
    # -fms-extensions enables anonymous struct embedding (struct foo; inside union)
    # which is used in kernel v7.0+ struct ns_common and similar types.
    # Suppress the resulting -Wmicrosoft-anon-tag warning.
    "-fms-extensions", "-Wno-microsoft-anon-tag",
    "-Wno-unknown-warning-option", "-Qunused-arguments",
    "-Wno-pointer-sign", "-Wno-array-bounds", "-Wno-gnu",
    "-Wno-unused-but-set-variable", "-Wno-unused-const-variable",
    "-Wno-implicit-function-declaration", "-Wno-implicit-int",
    "-Wno-return-type", "-Wno-strict-prototypes",
    "-Wno-format", "-Wno-sign-compare",
    "-std=gnu89",
]

DEFAULT_HARNESS_BODY = "    return 0;"


def subst_paths(s):
    """Replace {ksrc}/{shim} placeholders with the configured paths."""
    return s.replace("{ksrc}", str(KSRC)).replace("{shim}", str(SHIM))


def load_target(name):
    """Load one target's config and C fragments from targets/<name>/."""
    tdir = TARGETS_DIR / name
    if not tdir.is_dir():
        raise SystemExit(f"targets/{name}: directory not found (listed in ORDER)")
    cfg_path = tdir / "target.json"
    cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}

    body_path = tdir / "harness.c"
    cfg["harness_body"] = (
        body_path.read_text() if body_path.exists() else DEFAULT_HARNESS_BODY
    )

    # Pre-include text: shared snippets first (in listed order), then the
    # target's own pre_include.h. Concatenated verbatim, no separators.
    pre = ""
    for snippet in cfg.get("pre_include_shared", []):
        pre += (TARGETS_DIR / "_shared" / snippet).read_text()
    local_pre = tdir / "pre_include.h"
    if local_pre.exists():
        pre += local_pre.read_text()
    cfg["pre_include"] = pre

    preamble_path = tdir / "preamble.h"
    cfg["preamble"] = preamble_path.read_text() if preamble_path.exists() else ""
    return cfg


def load_targets():
    """Read targets/ORDER and each listed target's configuration."""
    order = [
        line.strip()
        for line in (TARGETS_DIR / "ORDER").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    return {name: load_target(name) for name in order}


def resolve_candidates(paths):
    """Resolve a candidate-path list ({ksrc}/{shim} placeholders) to one Path.

    A single-entry list is returned as-is (the caller handles a missing
    file); with several candidates the first existing one wins, falling
    back to the first entry so the caller reports it as missing.
    """
    resolved = [Path(subst_paths(p)) for p in paths]
    if len(resolved) == 1:
        return resolved[0]
    return next((p for p in resolved if p.exists()), resolved[0])


def compile_harness(src_name, src_path, cfg, out_path):
    """Compile a kernel source file with a BPF harness wrapper."""
    safe_name = src_name.replace('-', '_').replace('.', '_')
    extra_includes = [
        resolve_candidates(entry) for entry in cfg.get("extra_includes", [])
    ]
    harness_content = (
        (TARGETS_DIR / "harness_template.c").read_text()
        .replace("@SRC_NAME@", src_name)
        .replace("@SRC_PATH@", str(src_path))
        .replace("@SAFE_NAME@", safe_name)
        .replace("@HARNESS_BODY@", cfg["harness_body"])
        .replace("@EXTRA_INCLUDES@", "\n".join(f'#include "{p}"' for p in extra_includes))
        .replace("@EXTRA_PRE_INCLUDE@", subst_paths(cfg["pre_include"]))
        .replace("@EXTRA_PREAMBLE@", cfg["preamble"])
    )

    harness_path = OUTPUT / f"{src_name}_harness.c"
    harness_path.write_text(harness_content)

    extra_cflags = [subst_paths(f) for f in cfg.get("extra_cflags", [])]
    extra_early_cflags = [subst_paths(f) for f in cfg.get("extra_early_cflags", [])]
    # extra_early_cflags must come AFTER the compiler executable (BPF_CFLAGS[0])
    # but BEFORE the standard include paths in BPF_CFLAGS[1:], so that
    # module-specific -I paths shadow the standard shim paths.
    cmd = [BPF_CFLAGS[0]] + extra_early_cflags + BPF_CFLAGS[1:] + extra_cflags + ["-c", str(harness_path), "-o", str(out_path)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, cwd=str(KSRC))

    # Filter warnings
    errors = [l for l in result.stderr.splitlines() if 'error:' in l]
    if result.returncode != 0:
        return False, errors

    # NOTE: We do NOT run pahole -J here.
    # clang -target bpf -g already generates correct .BTF and .BTF.ext sections,
    # including the DATASEC entry for .maps that libbpf requires.
    # Running pahole -J would overwrite this BTF and REMOVE the DATASEC,
    # causing libbpf to fail with "DATASEC '.maps' not found".

    # Strip .BTF.ext (function-info / line-info) from the object.
    # This section causes the BPF verifier to look up the program's ctx type
    # in btf_vmlinux, which is absent on this kernel (no /sys/kernel/btf/).
    # Without .BTF.ext the verifier skips that check entirely while the
    # .BTF section (needed for map key/value types) is preserved.
    strip_result = subprocess.run(
        [LLVM_OBJCOPY, "--remove-section=.BTF.ext", str(out_path)],
        capture_output=True, text=True
    )
    if strip_result.returncode != 0:
        # Non-fatal: log but don't fail the compile step
        errors.append(f"[warn] llvm-objcopy strip .BTF.ext failed: {strip_result.stderr.strip()}")

    return True, errors


def run_veristat(obj_files):
    """Run veristat on a list of BPF object files, with verbose log."""
    if not os.path.isfile(VERISTAT):
        return 0, "(veristat not available - skipped)", ""

    veristat_cmd = [VERISTAT]
    if os.environ.get("BPF_VERISTAT_SUDO", ""):
        veristat_cmd = ["sudo"] + veristat_cmd

    try:
        verbose_out = OUTPUT / "veristat_verbose_step1.txt"
        verbose_result = subprocess.run(
            veristat_cmd + ["-v"] + obj_files,
            capture_output=True, timeout=600
        )
        vout = verbose_result.stdout.decode('utf-8', errors='replace')
        verr = verbose_result.stderr.decode('utf-8', errors='replace')
        verbose_out.write_text(vout + "\nSTDERR:\n" + verr)

        result = subprocess.run(
            veristat_cmd + obj_files,
            capture_output=True, timeout=600
        )
        result_stdout = result.stdout.decode('utf-8', errors='replace')
        result_stderr = result.stderr.decode('utf-8', errors='replace')
        return result.returncode, result_stdout, result_stderr
    except FileNotFoundError:
        return 0, "(veristat not runnable - skipped)", ""
    except subprocess.TimeoutExpired:
        return 1, "", "veristat timed out"


def main():
    import argparse
    parser = argparse.ArgumentParser(description="BPF Kernel Verification Pipeline")
    parser.add_argument(
        "--compile-only", action="store_true",
        help="Only compile harnesses; skip the veristat verification step."
    )
    args = parser.parse_args()

    print("=" * 70)
    print("BPF Kernel Verification Pipeline")
    print(f"Kernel source: {KSRC}")
    print(f"Output dir:    {OUTPUT}")
    print("=" * 70)

    targets = load_targets()

    compiled_ok = []
    compiled_fail = []

    print("\n--- Phase 1: Compiling kernel files to BPF ---")
    for name, cfg in targets.items():
        if "src" not in cfg:
            print(f"  [SKIP] {name}: no src in target.json")
            continue
        src = resolve_candidates(cfg["src"])
        if not src.exists():
            print(f"  [SKIP] {name}: source not found")
            continue

        out = OUTPUT / f"{name}.bpf.o"

        ok, errors = compile_harness(name, src, cfg, out)
        if ok:
            compiled_ok.append((name, out))
            print(f"  [OK]   {name}")
        else:
            first_err = errors[0][:200] if errors else "unknown error"
            compiled_fail.append((name, first_err))
            print(f"  [FAIL] {name}: {first_err}")

    print(f"\nCompiled: {len(compiled_ok)} OK, {len(compiled_fail)} FAIL")

    if not compiled_ok:
        print("No files compiled successfully!")
        sys.exit(1)

    if args.compile_only:
        print("\n--compile-only: skipping veristat.")
        return

    print("\n--- Phase 2: Running veristat ---")
    obj_files = [str(o) for _, o in compiled_ok]
    rc, stdout, stderr = run_veristat(obj_files)

    print(stdout)
    if stderr:
        # Only show non-libbpf-skip messages
        important = [l for l in stderr.splitlines()
                     if 'skipping' not in l and l.strip()]
        if important:
            print("STDERR:", '\n'.join(important[:10]))

    print(f"\nveristat exit: {rc}")

    # Save results
    results_file = OUTPUT / "results.txt"
    with open(results_file, 'w') as f:
        f.write("BPF Kernel Verification Pipeline Results\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Compiled OK ({len(compiled_ok)}):\n")
        for name, _ in compiled_ok:
            f.write(f"  {name}\n")
        f.write(f"\nCompiled FAIL ({len(compiled_fail)}):\n")
        for name, err in compiled_fail:
            f.write(f"  {name}: {err}\n")
        f.write("\n" + "=" * 70 + "\n")
        f.write("Veristat Results:\n")
        f.write(stdout)
        if stderr:
            f.write("\nVeristat STDERR:\n" + stderr)

    print(f"\nResults saved to: {results_file}")

    if rc != 0:
        sys.exit(rc)


if __name__ == '__main__':
    main()
