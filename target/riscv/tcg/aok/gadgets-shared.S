/*
 * AOK gadgets for RISC-V guests: the ones shared with iSH-AOK.
 *
 * The integer gadgets that touch nothing but guest registers, and the fused
 * pairs made of them, are not written here. shared/ holds iSH-AOK's own
 * sources for them (jit/guest-riscv64/alu.S, frag.h and pairs.h there),
 * copied by scripts/aok-gadgets-sync.sh and assembled as they are: what is
 * improved there arrives here with the next copy. Do not edit them here.
 *
 * This file is the other half of the arrangement, the definitions a host of
 * those sources owes them (frag.h, "A second host"): the two registers, how
 * a gadget begins and ends, and which of the gadgets pairs.h names this host
 * has (shared/host-gadgets.h, written by the same script from what this
 * file assembles to).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define RV_GADGET_HOST qemu
#define AOK_ASM_OWN_GADGET
#include "accel/tcg/aok-asm.h"

/* aok_gadget_rv_NAME, as gadgets.S names its own. */
.macro .gadget name
    .balign 16
    .globl SYM(aok_gadget_rv_\name)
SYM(aok_gadget_rv_\name):
.endm

#include "shared/host-gadgets.h"

    .text
#include "shared/alu.S"

/* frag.h's two bodies that are gadgets of files this host does not share. */
f_gadget mov_const
f_gadget addi
