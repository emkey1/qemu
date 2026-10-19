#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Runs the TCG tests for each guest in build/ under one backend of the hybrid.
#   ci-check-tcg.sh on|off    (on: TCTI, off: the JIT)
set -euo pipefail

tcti=$1
build=$(cd build && pwd)
wrappers=$(mktemp -d)
status=0

for target in x86_64 aarch64; do
  wrapper=$wrappers/qemu-system-$target
  printf '#!/bin/sh\nexec %s -accel tcg,tcti=%s "$@"\n' \
    "$build/qemu-system-$target" "$tcti" >"$wrapper"
  chmod +x "$wrapper"
  make -C "$build" "run-tcg-tests-$target-softmmu" QEMU="$wrapper" || status=1
done

exit $status
