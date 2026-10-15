#!/bin/sh
# aok-host-gadgets.sh -- write each front end's shared/host-gadgets.h: for
# every gadget its pair table (shared/pairs.h) names, whether the front end
# has it (HOST_name 1 or 0). "Has" is read off the assembled
# gadgets-shared.S, so it cannot disagree with the code. Run it after
# adding, renaming or removing a gadget a pair table names, or after editing
# a table. Needs a C compiler that assembles for AArch64.
#
# The shared/ directories hold the gadget sources taken from iSH-AOK on
# 2026-10-14 (shared/SOURCE there); they are this tree's own and are edited
# here.
set -e
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# one FRONT-END-DIR SYMBOL-PREFIX NAMES
one() {
    dir=$here/target/$1/tcg/aok
    for n in $3; do echo "#define HOST_$n 0"; done > "$dir/shared/host-gadgets.h"
    ${CC:-cc} -arch arm64 -c -I"$here/include" -I"$dir" \
        -o "$tmp/probe.o" "$dir/gadgets-shared.S"
    have=$(nm "$tmp/probe.o" | sed -n "s/.* T _*$2//p" | sort -u)
    {
        echo "/* Written by scripts/aok-host-gadgets.sh: which of the gadgets the"
        echo " * pair table names this front end has. Do not edit. */"
        for n in $3; do
            if echo "$have" | grep -qx "$n"; then echo "#define HOST_$n 1"; else echo "#define HOST_$n 0"; fi
        done
    } > "$dir/shared/host-gadgets.h"
    echo "$1: $(grep -c ' 1$' "$dir/shared/host-gadgets.h") of $(echo "$3" | wc -w | tr -d ' ') pairable gadgets"
}
# RISC-V's table marks a pairable gadget #define F_name 1; AArch64's names
# its family, #define F_name f_family, args. (A front end not in this tree is
# skipped.)
t=$here/target/riscv/tcg/aok/shared/pairs.h
[ ! -f "$t" ] || one riscv aok_gadget_rv_ "$(sed -n 's/^#define F_\([A-Za-z0-9_]*\) 1$/\1/p' "$t" | sort -u)"
t=$here/target/arm/tcg/aok/shared/pairs.h
[ ! -f "$t" ] || one arm aok_gadget_a64_ "$(sed -n 's/^#define F_\([A-Za-z0-9_]*\) f_.*/\1/p' "$t" | sort -u)"
