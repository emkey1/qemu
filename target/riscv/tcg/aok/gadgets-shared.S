/*
 * AOK gadgets for RISC-V guests: the ones taken from iSH-AOK.
 *
 * The integer gadgets, the loads and stores, the branches, and the fused
 * pairs made of them are in shared/: iSH-AOK's sources for them
 * (jit/guest-riscv64/alu.S, frag.h and pairs.h there), taken on 2026-10-14
 * and this tree's own since (shared/SOURCE).
 *
 * This file is what a host of those sources gives them (frag.h, "A second
 * host"): the registers, how a gadget begins and ends, how guest memory is
 * reached, how a TB is left, and which of the gadgets pairs.h names this
 * host has (shared/host-gadgets.h, which scripts/aok-host-gadgets.sh writes
 * from what this file assembles to).
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

/*
 * The address of an access, and what a load or store body keeps across the
 * access. Nothing here survives a call to C that is not saved around it:
 * every callee-saved register is aok_tb_exec's (aok-asm.h).
 */
_addr   .req x7
_sav    .req x6
_savw   .req w6

/* The dispatch of a body that has already moved _ip past the next word. */
.macro gret_ahead
    ldr x9, [_ip, #-8]
    br x9
.endm

/* ---- Guest memory ----------------------------------------------------------
 *
 * Stream of a load or store: [gadget][reg offset][rs1 offset][imm][word],
 * the last word this host's own: the insn in its low half and, above it, the
 * insn's distance from the TB's first.
 *
 * The softmmu fast path, as TCG's own backends inline it: index this TB's
 * fast table by the page number (folded, CPU_TLB_INDEX_FOLD), compare the
 * entry's tag with the address, and on a match the entry's addend turns the
 * guest address into a host one. The tag is compared with the address's page
 * AND its low alignment bits, so only an aligned access to a page with no
 * flags set hits; a misaligned one, MMIO, a watched or not-yet-dirty page
 * and a real miss all leave by the slow path, which is cputlb's.
 *
 * The slow path does the whole access in C, and may raise a guest exception
 * and not return. It is told the insn's pc and opcode, which it stores
 * first, so the CPU state is exact there with nothing to unwind. When it
 * does return, the body still makes its access: of the frame's scratch
 * word, where a load finds the value C read, and where a store's write goes
 * nowhere.
 */
#define TLB_FOLD        8       /* CPU_TLB_INDEX_FOLD */
#define TLB_SHIFT       7       /* TARGET_PAGE_BITS - CPU_TLB_ENTRY_BITS */
#define TLBE_READ       0
#define TLBE_WRITE      8
#define TLBE_ADDEND     24

.macro rv_tlb_probe size, id, tag
    ldp x9, x10, [_tlb]         /* mask, table */
    eor x11, _addr, _addr, lsr #TLB_FOLD
    and x9, x9, x11, lsr #TLB_SHIFT
    add x10, x10, x9
    ldr x11, [x10, #\tag]
    ldr x10, [x10, #TLBE_ADDEND]
    .if \size == 8
    and x9, _addr, #0xfffffffffffff000
    .else
    and x9, _addr, #(0xfffffffffffff000 | (\size / 8 - 1))
    .endif
    cmp x11, x9
    b.ne handle_miss_\id
    add _addr, _addr, x10
back_\id:
.endm

.macro read_prep size, id, ahead=0
    rv_tlb_probe \size, \id, TLBE_READ
.endm
.macro write_prep size, id, ahead=0
    rv_tlb_probe \size, \id, TLBE_WRITE
.endm
.macro write_done size, id
.endm

/* (_ip is \ahead bytes past the body's operands: the last is this host's) */
.macro read_bullshit size, id, ahead=0
handle_miss_\id:
    aok_fp_end
    ldr x2, [_ip, #-(\ahead + 8)]
    str _sav, [sp, #-16]!
    mov x0, _cpu
    mov x1, _addr
    and x3, x2, #0xffffffff     /* insn */
    add x2, _pc, x2, lsr #32    /* pc */
    bl SYM(aok_rv_helper_load\size)
    ldr _sav, [sp], #16
    str x0, [x29, #AOK_FRAME_SCRATCH]
    add _addr, x29, #AOK_FRAME_SCRATCH
    b back_\id
.endm
.macro write_bullshit size, id, ahead=0
handle_miss_\id:
    aok_fp_end
    ldr x3, [_ip, #-(\ahead + 8)]
    mov x0, _cpu
    mov x1, _addr
    mov x2, _sav                /* the value */
    and x4, x3, #0xffffffff
    add x3, _pc, x3, lsr #32
    bl SYM(aok_rv_helper_store\size)
    add _addr, x29, #AOK_FRAME_SCRATCH
    b back_\id
.endm

/* ---- Leaving a TB ----------------------------------------------------------
 *
 * A way out is aok_gadget_goto's two operands, [pc delta][slot], and a guest
 * code address in the stream is its distance from the TB's entry pc.
 *
 * Each way out is its own copy of aok_goto_tail rather than a jump to it, so
 * that each ends in an indirect branch of its own: through the one in
 * aok_goto_tail every transition between TBs in the guest left by a single
 * branch instruction of the host, which no predictor can follow (iSH-AOK's
 * branch_dispatch has the measurements).
 */
#define F_WAY_WORDS 2
.macro branch_leave off
    ldp x9, x10, [_ip, #\off]
    ldr w11, [_exitreq]
    add _pc, _pc, x9
    ldr _ip, [x10]
    str _pc, [_pcp]
    tbnz w11, #31, 7f
    gret AOK_ENTER_WORDS
7:  b SYM(aok_exit_requested)   /* (a test-and-branch does not reach it) */
.endm
.macro pc_param reg
    add \reg, _pc, \reg
.endm

#include "shared/host-gadgets.h"

    .text

/*
 * jalr, under the name of iSH-AOK's jalr that finds its target without
 * leaving the stream, which is what this one does its own way:
 * [rd offset][rs1 offset][imm][link delta][flags | cflags << 32][cs_base].
 * The target is computed from rs1 before the link is written, since rd may be
 * rs1; then aok_gadget_rv_lookup's code, entered with the target in x10.
 * Defined before the shared sources, whose pairs may end in it.
 */
.macro f_jalr_cached_body id, last, fn=_, fm=_, res=0
    ldp x9, x10, [_ip]
    ldp x11, x13, [_ip, #16]
    f_src 10, x10, \fn
    add x13, _pc, x13
    add x10, x10, x11
    bic x10, x10, #1
    str x13, [_cpu, x9]
    str x10, [_pcp]
    add _ip, _ip, #32
    b SYM(aok_rv_lookup_pc)
.endm
.macro f_jalr_cached_stub id, last
.endm

#include "shared/alu.S"

/* frag.h's bodies that are gadgets of files this host does not share. */
f_gadget mov_const
f_gadget addi
f_gadget b
.irp name, lb, lbu, lh, lhu, lw, lwu, ld, sb, sh, sw, sd
f_gadget \name
.endr
f_gadget jalr_cached

/*
 * flw: lwu into an FP register, NaN-boxed (the upper half all ones). Built
 * of the same parts as the loads; in no pair.
 */
.gadget flw
    ldr _sav, [_ip]
    ldp x9, x10, [_ip, #8]
    add _ip, _ip, #40
    ldr _addr, [_cpu, x9]
    add _addr, _addr, x10
    read_prep 32, flw, 8
    ldr w11, [_addr]
    orr x11, x11, #0xffffffff00000000
    str x11, [_cpu, _sav]
    gret_ahead
    read_bullshit 32, flw, 8
