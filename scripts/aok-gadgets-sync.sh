#!/bin/sh
# aok-gadgets-sync.sh [--check] [ISH_AOK_CHECKOUT]
#
# The AOK gadgets of a front end that iSH-AOK also has are iSH-AOK's sources,
# kept here as copies (target/riscv/tcg/aok/shared). This brings the copies
# up to date with a checkout of iSH-AOK (default ../ish-AOK), or with
# --check says whether they are.
#
# It also writes shared/host-gadgets.h: for every gadget iSH-AOK's pair table
# names, whether this front end has it (HOST_name 1 or 0). "Has" is read off
# the assembled gadgets-shared.S, so it cannot disagree with the code.
# Needs a C compiler that assembles for AArch64.
set -e
check=
[ "$1" = --check ] && { check=1; shift; }
here=$(cd "$(dirname "$0")/.." && pwd)
src=${1:-$here/../ish-AOK}/jit/guest-riscv64
dst=$here/target/riscv/tcg/aok/shared
[ -f "$src/alu.S" ] || { echo "no iSH-AOK checkout at ${1:-$here/../ish-AOK}" >&2; exit 2; }

if [ -n "$check" ]; then
    for f in alu.S frag.h pairs.h; do
        cmp -s "$src/$f" "$dst/$f" || { echo "shared/$f differs from iSH-AOK's: run $0" >&2; exit 1; }
    done
    echo "shared gadget sources match $(git -C "$src" rev-parse --short HEAD)"
    exit 0
fi

mkdir -p "$dst"
cp "$src/alu.S" "$src/frag.h" "$src/pairs.h" "$dst/"
{
    echo "iSH-AOK jit/guest-riscv64 (alu.S, frag.h, pairs.h)"
    echo "commit $(git -C "$src" rev-parse HEAD)"
    git -C "$src" diff --quiet HEAD -- alu.S frag.h pairs.h || echo "with uncommitted changes"
    echo "licence: GPL-2.0-only OR GPL-3.0-only (iSH-AOK's LICENSE.md: GPLv3, and GPLv2 as well for"
    echo "what was contributed after its commit 0e3a4144, which all three files were)"
} > "$dst/SOURCE"

# Which gadgets do we have? Assemble with every HOST_ at 0 (no pairs), and look.
names=$(sed -n 's/^#define F_\([A-Za-z0-9_]*\) 1$/\1/p' "$dst/pairs.h" | sort -u)
tmp=$(mktemp -d)
for n in $names; do echo "#define HOST_$n 0"; done > "$dst/host-gadgets.h"
${CC:-cc} -arch arm64 -c -I"$here/include" -I"$here/target/riscv/tcg/aok" \
    -o "$tmp/probe.o" "$here/target/riscv/tcg/aok/gadgets-shared.S"
have=$(nm "$tmp/probe.o" | sed -n 's/.* T _*aok_gadget_rv_//p' | sort -u)
{
    echo "/* Written by scripts/aok-gadgets-sync.sh: which of the gadgets that"
    echo " * iSH-AOK's pair table names this front end has. Do not edit. */"
    for n in $names; do
        if echo "$have" | grep -qx "$n"; then echo "#define HOST_$n 1"; else echo "#define HOST_$n 0"; fi
    done
} > "$dst/host-gadgets.h"
rm -rf "$tmp"
echo "copied from $(git -C "$src" rev-parse --short HEAD): $(grep -c ' 1$' "$dst/host-gadgets.h") of $(echo "$names" | wc -w | tr -d ' ') pairable gadgets here"
