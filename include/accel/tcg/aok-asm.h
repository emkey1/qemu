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
_fpok    .req x26
_fpact   .req x27
_ip      .req x28

/* The enter gadget and its operands: what a jump between streams skips. */
#define AOK_ENTER_WORDS 3

/* aok_tb_exec's frame: where it keeps AokCPU.host_fpsr, off x29. */
#define AOK_FRAME_FPSR  96

/*
 * Before any call to C, and before leaving the stream.
 *
 * While _fpact is set the host's FPSR holds exactly the exception flags the
 * stream's FP gadgets have raised: the first of them cleared it. C code may
 * raise host flags of its own, or want the guest's, so the stream's are
 * moved to *AokCPU.host_fpsr first, for the front end to fold into its own
 * FP status, and the next FP gadget starts over. Clobbers x14-x17.
 */
.macro aok_fp_end
    cbz _fpact, 9f
    mrs x16, fpsr
    ldr x17, [x29, #AOK_FRAME_FPSR]
    mov _fpact, #0
    ldr w15, [x17]
    orr w15, w15, w16
    str w15, [x17]
9:
.endm

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

/* (a file of gadgets under another prefix defines its own: AOK_ASM_OWN_GADGET) */
#ifndef AOK_ASM_OWN_GADGET
.macro .gadget name
    .balign 16
    .globl SYM(aok_gadget_\name)
SYM(aok_gadget_\name):
.endm
#endif

#endif
