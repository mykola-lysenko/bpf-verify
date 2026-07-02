#!/bin/bash
# run.sh — build and run userspace property-fuzzing harnesses under
# AddressSanitizer + UBSan.
#
# Usage: run.sh [--iters N] [--seed S] [harness ...]
# With no harness names, runs every userspace/harnesses/*.c.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "${HERE}")"
CC="${CC:-cc}"
ITERS="5000000"
SEED="0x1234567"
SANFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all -g -O1"
# Kernel source tree targets include real .c files from (override with BPF_KSRC).
export KSRC="${BPF_KSRC:-${REPO}/deps/bpf-uml-selftests/uml-veristat/.build/bpf-next}"

names=()
while [ $# -gt 0 ]; do
	case "$1" in
		--iters) ITERS="$2"; shift 2 ;;
		--seed)  SEED="$2"; shift 2 ;;
		*)       names+=("$1"); shift ;;
	esac
done
if [ ${#names[@]} -eq 0 ]; then
	for f in "${HERE}"/harnesses/*.c; do
		names+=("$(basename "${f}" .c)")
	done
fi

BUILD="$(mktemp -d)"
trap 'rm -rf "${BUILD}"' EXIT
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0"

fail=0
for name in "${names[@]}"; do
	src="${HERE}/harnesses/${name}.c"
	[ -f "${src}" ] || { echo "run.sh: no such harness ${name}"; fail=1; continue; }
	bin="${BUILD}/${name}"
	# Optional per-harness compiler flags (may reference $KSRC, $HERE, $REPO).
	EXTRA=""
	if [ -f "${HERE}/harnesses/${name}.flags" ]; then
		EXTRA="$(eval echo "$(cat "${HERE}/harnesses/${name}.flags")")"
	fi
	if ! "${CC}" ${SANFLAGS} -I"${HERE}" -include "${HERE}/khost.h" ${EXTRA} \
			"${src}" "${HERE}/fuzz_main.c" -o "${bin}" 2>"${BUILD}/${name}.cc.log"; then
		echo "=== ${name}: BUILD FAILED ==="
		cat "${BUILD}/${name}.cc.log"
		fail=1
		continue
	fi
	echo "=== ${name} (iters=${ITERS}) ==="
	if ! "${bin}" --iters "${ITERS}" --seed "${SEED}"; then
		fail=1
	fi
done

exit "${fail}"
