#!/bin/bash
# build_runner.sh — compile tools/bpf_runner against the uml-veristat libbpf.
#
# Produces tools/bpf_runner. Locates libbpf.a + headers inside the submodule's
# .build tree (bpftool build), falling back to a system libbpf. The runner is
# executed inside the UML guest (host-arch userspace via hostfs), so a normal
# host compile is correct.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "${HERE}")"
UML_BUILD="${REPO}/deps/bpf-uml-selftests/uml-veristat/.build"
CC="${CC:-cc}"
OUT="${HERE}/bpf_runner"

# Prefer a libbpf.a that ships its include/bpf/ headers.
LIBBPF_A=""
LIBBPF_INC=""
for cand in \
	"${UML_BUILD}/bpftool-output/libbpf" \
	"${UML_BUILD}/selftests-output/tools/build/libbpf"; do
	if [ -f "${cand}/libbpf.a" ] && [ -d "${cand}/include" ]; then
		LIBBPF_A="${cand}/libbpf.a"
		LIBBPF_INC="${cand}/include"
		break
	fi
done

if [ -n "${LIBBPF_A}" ]; then
	echo "build_runner: using ${LIBBPF_A}"
	"${CC}" -O2 -Wall -o "${OUT}" "${HERE}/bpf_runner.c" \
		-I"${LIBBPF_INC}" "${LIBBPF_A}" -lelf -lz
else
	echo "build_runner: submodule libbpf not found, trying system -lbpf"
	"${CC}" -O2 -Wall -o "${OUT}" "${HERE}/bpf_runner.c" -lbpf -lelf -lz
fi

echo "build_runner: wrote ${OUT}"
