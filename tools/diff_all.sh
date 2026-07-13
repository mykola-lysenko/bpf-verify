#!/bin/bash
# diff_all.sh — run every native-vs-BPF differential target and gate on the result.
#
# Iterates diff/*/ (any directory with a compute.h), runs tools/diff.sh for
# each, and exits non-zero if any target fails to build, run, or agree.
# Per-target logs land in ${BPF_OUTPUT:-output2}/<name>_diff.log; the last
# line of each (the compare verdict or the error) is echoed to the summary.
#
# Usage: diff_all.sh [--iters N]
# Env:   DIFF_ITERS (default 20000; --iters wins), plus the same BPF_* /
#        UML_KERNEL environment tools/diff.sh consumes.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "${HERE}")"
OUT="${BPF_OUTPUT:-${REPO}/output2}"
mkdir -p "${OUT}"

ITERS="${DIFF_ITERS:-20000}"
while [ $# -gt 0 ]; do
	case "$1" in
		--iters) ITERS="$2"; shift 2 ;;
		*) echo "diff_all.sh: unknown arg $1"; exit 2 ;;
	esac
done

pass=()
fail=()
for d in "${REPO}"/diff/*/; do
	name="$(basename "${d}")"
	[ -f "${d}/compute.h" ] || continue
	log="${OUT}/${name}_diff.log"
	echo "--- diff: ${name} (${ITERS} iters) ---"
	if bash "${HERE}/diff.sh" "${name}" --iters "${ITERS}" > "${log}" 2>&1; then
		echo "    $(tail -1 "${log}")"
		pass+=("${name}")
	else
		echo "    FAILED; log tail:"
		tail -5 "${log}" | sed 's/^/    | /'
		fail+=("${name}")
	fi
done

echo
echo "diff_all: ${#pass[@]} agree, ${#fail[@]} failed of $(( ${#pass[@]} + ${#fail[@]} )) targets (${ITERS} iters each)"
if [ "${#fail[@]}" -gt 0 ]; then
	echo "failed: ${fail[*]}"
	exit 1
fi
