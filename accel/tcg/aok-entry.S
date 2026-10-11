/*
 * AOK gadgets: entering and leaving a stream, and the gadgets every front
 * end shares. See include/accel/tcg/aok.h for the register convention.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "accel/tcg/aok-asm.h"

    .text

/*
 * uintptr_t aok_tb_exec(CPUArchState *env, const void *stream,
 *                       const AokCPU *cpu);
 */
    .balign 16
    .globl SYM(aok_tb_exec)
SYM(aok_tb_exec):
    stp x29, x30, [sp, #-112]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp x27, x28, [sp, #80]
    mov _cpu, x0
    mov _ip, x1
    ldp _exitreq, _pcp, [x2]
    ldp _jc, _bps, [x2, #16]
    ldr x9, [x2, #32]
    mov _fpact, #0
    str x9, [x29, #AOK_FRAME_FPSR]
    gret

/* Leave the stream: x0 is aok_tb_exec's return value. */
    .balign 16
    .globl SYM(aok_exit)
SYM(aok_exit):
    aok_fp_end
    ldp x19, x20, [sp, #16]
    ldp x21, x22, [sp, #32]
    ldp x23, x24, [sp, #48]
    ldp x25, x26, [sp, #64]
    ldp x27, x28, [sp, #80]
    ldp x29, x30, [sp], #112
    ret

/*
 * [tb][tlb fast offset] -- how the main loop enters a TB. As TCG's TBs start
 * with the same test: leave if an exit has been requested, without having
 * run any of the TB. Then take the entry pc, which everything pc-relative in
 * the TB is measured from, and the address of the softmmu fast table for the
 * TB's mmu index.
 *
 * A jump from another stream does not come through here. It has the pc
 * already, the fast table is the same one (the two TBs have the same flags,
 * or they would not be linked), and it makes the test itself: so it
 * continues AOK_ENTER_WORDS words in, past this gadget and its operands.
 */
.gadget enter
    ldr w9, [_exitreq]
    tbnz w9, #31, 1f
    ldr x10, [_ip, #8]
    ldr _pc, [_pcp]
    add _tlb, _cpu, x10
    gret 2
1:  ldr x0, [_ip]
    orr x0, x0, #3              /* TB_EXIT_REQUESTED */
    b SYM(aok_exit)

/* [value] */
.gadget exit_tb
    ldr x0, [_ip]
    b SYM(aok_exit)

/*
 * [pc delta][slot] -- leave the TB for the one at entry pc + delta: store
 * that pc, and continue in the stream the slot points to, past its enter
 * gadget, unless an exit has been requested. Then return to the main loop
 * with no TB to link from: env->pc says where to resume. A front end's own
 * branch gadgets load x9 and x10 and tail-call aok_goto_tail.
 *
 * What a slot holds is therefore AOK_ENTER_WORDS words before the gadget to
 * run: a TB's start, or that far before one of this TB's own stubs.
 */
.gadget goto
    ldp x9, x10, [_ip]
    .globl SYM(aok_goto_tail)
SYM(aok_goto_tail):
    add _pc, _pc, x9
    ldr w11, [_exitreq]
    ldr _ip, [x10]
    str _pc, [_pcp]
    tbnz w11, #31, SYM(aok_exit_requested)
    gret AOK_ENTER_WORDS

/* An exit was requested on the way from one stream to the next. */
    .globl SYM(aok_exit_requested)
SYM(aok_exit_requested):
    mov x0, #0
    b SYM(aok_exit)

/*
 * [flags | cflags << 32][cs_base] -- env->pc is set and the next TB is not
 * known at translation time: an indirect jump, or a direct one that may not
 * be linked. Continue in that TB if it exists and is one of ours, else return
 * to the main loop, which will find or make it. The operands are for a front
 * end's own lookup gadget, which falls back to aok_lookup_slow.
 */
.gadget lookup
    .globl SYM(aok_lookup_slow)
SYM(aok_lookup_slow):
    aok_fp_end
    mov x0, _cpu
    bl SYM(aok_lookup_tb_ptr)
    cbz x0, 1f
    mov _ip, x0
    gret
1:  b SYM(aok_exit)             /* x0 == 0: no TB to link from */
