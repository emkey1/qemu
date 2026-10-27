#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Runs the TCG tests for each guest in build/ under one backend of the hybrid.
#   ci-check-tcg.sh on|off|rcg    (on: TCTI, off: the JIT, rcg: TCTI with RCG)
set -euo pipefail

targets="x86_64 aarch64"
case $1 in
# RCG has gadgets for x86_64 guests only.
rcg) accel=tcti=on,rcg=on targets=x86_64 ;;
*) accel=tcti=$1 ;;
esac
build=$(cd build && pwd)
wrappers=$(mktemp -d)
status=0

for target in $targets; do
  wrapper=$wrappers/qemu-system-$target
  printf '#!/bin/sh\nexec %s -accel tcg,%s "$@"\n' \
    "$build/qemu-system-$target" "$accel" >"$wrapper"
  chmod +x "$wrapper"
  make -C "$build" "run-tcg-tests-$target-softmmu" QEMU="$wrapper" || status=1
done

# The RCG tests also pass if RCG takes nothing, so check that the first fault
# case's TB holds a rich op.
if [ "$1" = rcg ]; then
  test=$build/tests/tcg/x86_64-softmmu/rcg-faults
  at=$(nm "$test" | awk '$3 == "rcg_fault_0" { print $1 }')
  "$wrappers/qemu-system-x86_64" -monitor none -display none \
    -device isa-debug-exit,iobase=0xf4,iosize=0x4 -d op \
    -dfilter "0x$at+0x800" -D "$wrappers/op.log" -kernel "$test" || true
  if ! grep -q '^ *rich ' "$wrappers/op.log"; then
    echo "RCG took no instruction in rcg_fault_0" >&2
    status=1
  fi
fi

exit $status
