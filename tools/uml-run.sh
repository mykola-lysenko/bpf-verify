#!/bin/bash
# uml-run — run an arbitrary command inside the uml-veristat UML guest.
#
# The uml-veristat wrapper only runs veristat; this boots the same UML kernel
# (hostfs=/, so all host paths are visible) with an init script that runs the
# given command, captures its stdout/stderr and exit code, and halts.
#
# Usage: uml-run.sh <command> [args...]
# Env:   UML_KERNEL (default ~/.local/share/uml-veristat/linux), UML_MEM (512M)
set -euo pipefail

UML_BIN="${UML_KERNEL:-${HOME}/.local/share/uml-veristat/linux}"
[ -x "${UML_BIN}" ] || { echo "uml-run: UML kernel not found at ${UML_BIN}" >&2; exit 3; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
INIT="${WORK}/init.sh"
OUT="${WORK}/out"
RC="${WORK}/rc"

# The command is embedded verbatim; callers pass absolute paths (hostfs=/).
CMD="$*"
cat > "${INIT}" <<INIT_EOF
#!/bin/sh
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
${CMD} > ${OUT} 2>${OUT}.err
echo \$? > ${RC}
sync
halt -f 2>/dev/null || poweroff -f 2>/dev/null || echo o > /proc/sysrq-trigger
INIT_EOF
chmod +x "${INIT}"

"${UML_BIN}" \
	"mem=${UML_MEM:-512M}" \
	rootfstype=hostfs hostfs=/ rw \
	"init=${INIT}" \
	quiet loglevel=0 con=null con0=null >/dev/null 2>&1 || true

cat "${OUT}" 2>/dev/null || true
if [ -s "${OUT}.err" ]; then
	echo "--- stderr ---" >&2
	cat "${OUT}.err" >&2
fi
exit "$(cat "${RC}" 2>/dev/null || echo 3)"
