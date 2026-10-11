/*
 * AOK gadgets: definitions for the assembly sources (AArch64 host).
 * The register convention is described in include/accel/tcg/aok.h.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ACCEL_TCG_AOK_ASM_H
#define ACCEL_TCG_AOK_ASM_H

#ifdef __APPLE__
#define SYM(x) _##x
#else
#define SYM(x) x
#endif

_pc      .req x19
_cpu     .req x20
_exitreq .req x21
_pcp     .req x22
_tlb     .req x23
_jc      .req x24
_bps     .req x25
_ip      .req x28

/*
 * End a gadget: skip its \pop operand words and go to the gadget whose
 * address is the next word of the stream. The load and the add both start
 * from the old stream pointer, so neither waits for the other.
 */
.macro gret pop=0
    ldr x9, [_ip, #(\pop * 8)]
    add _ip, _ip, #(\pop * 8 + 8)
    br x9
.endm

.macro .gadget name
    .balign 16
    .globl SYM(aok_gadget_\name)
SYM(aok_gadget_\name):
.endm

#endif
