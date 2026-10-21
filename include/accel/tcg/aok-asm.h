/*
 * AOK gadgets: definitions for the assembly sources (AArch64 host).
 * The register convention is described in include/accel/tcg/aok.h.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ACCEL_TCG_AOK_ASM_H
#define ACCEL_TCG_AOK_ASM_H

#include "accel/tcg/aok-tlb.h"

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

/*
 * aok_tb_exec's frame, off x29: where it keeps AokCPU.host_fpsr, and
 * twenty-four bytes that are any gadget's to use between two dispatches.
 */
#define AOK_FRAME_FPSR  96
#define AOK_FRAME_SCRATCH 104

/*
 * Before any call to C, and before leaving the stream.
 *
 * While _fpact is set the host's FPSR holds exactly the exception flags the
 * stream's FP gadgets have raised: the first of them cleared it. C code may
 * raise host flags of its own, or want the guest's, so the stream's are
 * moved to *AokCPU.host_fpsr first, for the front end to fold into its own
 * FP status, and the next FP gadget starts over. Clobbers x14-x17.
 *
 * A front end may also have given the host's FPCR its guest's modes when it
 * set _fpact. QEMU's own code computes with FPCR zero, as every thread
 * starts, so that is put back.
 */
.macro aok_fp_end
    cbz _fpact, 9f
    mrs x16, fpsr
    ldr x17, [x29, #AOK_FRAME_FPSR]
    msr fpcr, xzr
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

/*
 * The body of a front end's lookup gadget, entered with the pc to go to in
 * x10 (and stored) and _ip at the two operands, [flags | cflags << 32]
 * [cs_base] of the TB the gadget is in. It is tb_lookup()'s first step: the
 * pc is hashed as tb_jmp_cache_hash_func() hashes it and both ways of
 * cpu->tb_jmp_cache are read; a TB there with these flags is jumped to, as
 * aok_goto_tail jumps, if it is a stream. Which is sound because nothing a
 * stream executes changes the flags. Anything else is aok_lookup_slow's.
 *
 * The second way is tried also when the first has the pc under other flags:
 * a kernel's code may run under two sets of them (x86: with the ss of a
 * syscall and with the null one an interrupt leaves), and then the two TBs
 * of one pc sit side by side.
 */
.macro aok_lookup_jc
    ldr x11, [_bps]
    eor x12, x10, x10, lsr #5
    cbnz x11, 3f
    lsr x13, x12, #5
    and x12, x12, #0x7f
    and x13, x13, #0x3f80
    orr x12, x12, x13               /* the hash */
    ldp x11, x9, [_ip]              /* what the TB must have */
    add x13, _jc, x12, lsl #4
    ldp x14, x15, [x13, #16]        /* tb, pc */
    cmp x15, x10
    b.ne 2f
    cbz x14, 2f
    ldp x15, x16, [x14, #8]         /* cs_base, flags | cflags << 32 */
    cmp x16, x11
    ccmp x15, x9, #0, eq
    b.eq 5f
2:  eor x12, x12, #1                /* the other way */
    add x13, _jc, x12, lsl #4
    ldp x14, x15, [x13, #16]
    cmp x15, x10
    b.ne 3f
    cbz x14, 3f
    ldp x15, x16, [x14, #8]
    cmp x16, x11
    ccmp x15, x9, #0, eq
    b.ne 3f
5:  ldrb w17, [x14, #28]            /* aok */
    cbz w17, 3f
    ldr w11, [_exitreq]
    ldr _ip, [x14, #32]             /* tc.ptr */
    mov _pc, x10
    tbnz w11, #31, 4f
    gret AOK_ENTER_WORDS
3:  b SYM(aok_lookup_slow)
4:  b SYM(aok_exit_requested)
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
