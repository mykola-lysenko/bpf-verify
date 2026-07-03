#!/bin/bash
# diff.sh — native-vs-BPF differential for one target.
#
# 1. builds the BPF differential object (real pipeline compilation),
# 2. builds the native reference (host, via the userspace shim),
# 3. runs the native reference -> expected outputs,
# 4. runs the BPF object in the UML guest -> BPF outputs,
# 5. diffs the two, reporting divergences with reproducing seeds.
#
# Usage: diff.sh <name> [--iters N] [--base S]
# Env:   same BPF_* as the pipeline (BPF_KSRC, BPF_CLANG, ...), BPF_RUNNER,
#        BPF_UML_RUN.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "${HERE}")"
NAME="${1:?usage: diff.sh <name> [--iters N] [--base S]}"; shift || true
ITERS="200000"
BASE="0x1234567"
while [ $# -gt 0 ]; do
	case "$1" in
		--iters) ITERS="$2"; shift 2 ;;
		--base)  BASE="$2"; shift 2 ;;
		*) echo "diff.sh: unknown arg $1"; exit 2 ;;
	esac
done

export KSRC="${BPF_KSRC:-${REPO}/deps/bpf-uml-selftests/uml-veristat/.build/bpf-next}"
OUT="${BPF_OUTPUT:-${REPO}/output2}"
mkdir -p "${OUT}"
RUNNER="${BPF_RUNNER:-${REPO}/tools/bpf_runner}"
UML_RUN="${BPF_UML_RUN:-${REPO}/tools/uml-run.sh}"
CC="${CC:-cc}"

tdir="${REPO}/diff/${NAME}"
[ -f "${tdir}/compute.h" ] || { echo "diff.sh: no diff/${NAME}/compute.h"; exit 2; }
[ -f "${tdir}/native.flags" ] || { echo "diff.sh: no diff/${NAME}/native.flags"; exit 2; }

echo "=== ${NAME}: build BPF differential object ==="
python3 "${HERE}/diff_build.py" "${NAME}" --out "${OUT}" || exit 1
BPF_OBJ="${OUT}/${NAME}_diff.bpf.o"

echo "=== ${NAME}: build native reference ==="
NATIVE_FLAGS="$(eval echo "$(cat "${tdir}/native.flags")")"
NAT_BIN="${OUT}/${NAME}_diff_native"
# shellcheck disable=SC2086
"${CC}" -O2 -g -fno-strict-aliasing -I"${REPO}/userspace" -I"${HERE}" \
	-include "${REPO}/userspace/khost.h" \
	-DDIFF_COMPUTE="\"${tdir}/compute.h\"" \
	${NATIVE_FLAGS} \
	"${HERE}/diff_native.c" -o "${NAT_BIN}" || { echo "native build failed"; exit 1; }

echo "=== ${NAME}: run native reference (${ITERS} iters) ==="
NAT_OUT="${OUT}/${NAME}_native.bin"
"${NAT_BIN}" --iters "${ITERS}" --base "${BASE}" --out "${NAT_OUT}" || exit 1

echo "=== ${NAME}: run BPF object in UML (${ITERS} iters) ==="
BPF_OUT="${OUT}/${NAME}_bpf.bin"
bash "${UML_RUN}" "${RUNNER}" --emit "${BPF_OUT}" --base "${BASE}" \
	--iters "${ITERS}" "${BPF_OBJ}" || { echo "BPF emit run failed"; exit 1; }

echo "=== ${NAME}: compare ==="
python3 "${HERE}/diff_compare.py" "${NAT_OUT}" "${BPF_OUT}" --base "${BASE}"
