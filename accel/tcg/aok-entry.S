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
 *                       uint32_t *exit_request, uint64_t *pc);
 */
    .balign 16
    .globl SYM(aok_tb_exec)
SYM(aok_tb_exec):
    stp x29, x30, [sp, #-96]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp x27, x28, [sp, #80]
    mov _cpu, x0
    mov _ip, x1
    mov _exitreq, x2
    mov _pcp, x3
    gret

/* Leave the stream: x0 is aok_tb_exec's return value. */
    .balign 16
    .globl SYM(aok_exit)
SYM(aok_exit):
    ldp x19, x20, [sp, #16]
    ldp x21, x22, [sp, #32]
    ldp x23, x24, [sp, #48]
    ldp x25, x26, [sp, #64]
    ldp x27, x28, [sp, #80]
    ldp x29, x30, [sp], #96
    ret

/*
 * [tb][tlb fast offset] -- the first gadget of every TB, linked jumps
 * included, as TCG's TBs start with the same test: leave if an exit has been
 * requested, without having run any of the TB. Then take the entry pc, which
 * everything pc-relative in the TB is measured from, and the address of the
 * softmmu fast table for the TB's mmu index.
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
 * that pc, and continue at the stream the slot points to. A front end's own
 * branch gadgets load x9 and x10 and tail-call aok_goto_tail.
 */
.gadget goto
    ldp x9, x10, [_ip]
    .globl SYM(aok_goto_tail)
SYM(aok_goto_tail):
    add x9, _pc, x9
    ldr _ip, [x10]
    str x9, [_pcp]
    gret

/*
 * env->pc is set and the next TB is not known at translation time: an
 * indirect jump, or a direct one that may not be linked. Continue in that TB
 * if it exists and is one of ours, else return to the main loop, which will
 * find or make it.
 */
.gadget lookup
    .globl SYM(aok_lookup_tail)
SYM(aok_lookup_tail):
    mov x0, _cpu
    bl SYM(aok_lookup_tb_ptr)
    cbz x0, 1f
    mov _ip, x0
    gret
1:  b SYM(aok_exit)             /* x0 == 0: no TB to link from */
