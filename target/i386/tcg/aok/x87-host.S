/*
 * AOK gadgets for x86 guests: the x87.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The x87 itself is not written here. Its arithmetic (80 bits, in integer
 * registers, exact to the hardware), its register stack, every D8-DF
 * instruction's register form, the transcendentals and what a memory form
 * does once it has its operand are in shared/: iSH-AOK's x87 sources,
 * which its JIT tests against 122,880 answers from an AMD Ryzen, taken on
 * 2026-10-14 and this tree's own since (shared/SOURCE).
 * shared/x87-arith.S says what a host owes them. This file is that: where
 * QEMU keeps the x87's state, how a gadget here reaches guest memory, and
 * the two instructions that only read a word of the state.
 *
 * QEMU's layout differs from the one the shared code thinks in, in two
 * places. TOP is not in the status word but beside it (fpstt), and the tags
 * are a byte a register, 1 for empty, where the shared code has a bit a
 * register, 1 for full. The four access macros convert; the registers
 * themselves (fpregs: a significand, then sign and exponent, in 16 bytes)
 * and the control word are as the shared code wants them.
 *
 * Nothing of softfloat's is touched: fp_status keeps whatever QEMU's own
 * helpers left there, for the instructions that are still theirs (FLDCW goes
 * through QEMU's helper for that reason: it sets softfloat's modes too).
 *
 * Included by gadgets.S, whose memory macros it uses.
 */

#define CPU_fp  AOK_X86_ENV_FPREGS
#define CPU_fcw AOK_X86_ENV_FPUC

/* Where a store's converted value goes first: aok_tmp, through x2. */
x87_wp .req x2

.macro gret_nomem pop=0
    gret \pop
.endm

.macro x87_ld_fsw r
    ldrh \r, [_cpu, #AOK_X86_ENV_FPUS]
    ldr w16, [_cpu, #AOK_X86_ENV_FPSTT]
    bfi \r, w16, #11, #3
.endm
.macro x87_st_fsw r
    and w16, \r, #0xffffc7ff
    strh w16, [_cpu, #AOK_X86_ENV_FPUS]
    ubfx w16, \r, #11, #3
    str w16, [_cpu, #AOK_X86_ENV_FPSTT]
.endm
/*
 * Eight bytes of 0 or 1 to a bit each: the multiplier has one bit a byte,
 * placed so that byte i's lands at bit 56 + i and no two products meet.
 */
.macro x87_ld_valid r
    ldr x16, [_cpu, #AOK_X86_ENV_FPTAGS]
    ldr x17, x87h_gather
    mul x16, x16, x17
    lsr x16, x16, #56
    eor \r, w16, #0xff
.endm
/* And back, through a table: the empty registers' bits to a byte each. */
.macro x87_st_valid r
    mvn w16, \r
    and x16, x16, #0xff
    adr x17, x87h_tags
    ldr x16, [x17, x16, lsl #3]
    str x16, [_cpu, #AOK_X86_ENV_FPTAGS]
.endm

/*
 * An x87 gadget's first operand word has the insn's distance from the TB's
 * first in its upper half, for this. With ES set, QEMU's fwait: #MF, or
 * with CR0.NE clear the FERR interrupt, after which the insn goes on.
 */
.macro x87_wait
    ldrh w8, [_cpu, #AOK_X86_ENV_FPUS]
    tbz w8, #7, .Lx87w\@
    bl x87h_mf
.Lx87w\@:
.endm

/* FCOMI's flags, from w9: the lazy state becomes them (CC_OP_EFLAGS). */
.macro x87_comi_flags
    str x9, [_cpu, #AOK_X86_ENV_CC_SRC]
    mov w10, #AOK_CC_OP_EFLAGS
    str w10, [_cpu, #AOK_X86_ENV_CC_OP]
.endm

/* FCMOV's flag: the translator has put flush_cc before the gadget. */
.macro x87h_flag dst, which
    ldr \dst, [_cpu, #AOK_X86_ENV_CC_SRC]
    .ifc \which,c
        and \dst, \dst, #1
    .endif
    .ifc \which,z
        ubfx \dst, \dst, #6, #1
    .endif
    .ifc \which,p
        ubfx \dst, \dst, #2, #1
    .endif
.endm

    .balign 8
x87h_gather:
    .quad 0x0102040810204080
x87h_tags:
    .set x87h_i, 0
    .rept 256
    .quad (x87h_i & 1) | ((x87h_i >> 1) & 1) << 8 | ((x87h_i >> 2) & 1) << 16 | ((x87h_i >> 3) & 1) << 24 | ((x87h_i >> 4) & 1) << 32 | ((x87h_i >> 5) & 1) << 40 | ((x87h_i >> 6) & 1) << 48 | ((x87h_i >> 7) & 1) << 56
    .set x87h_i, x87h_i + 1
    .endr

/* x1 is a memory form's address, which it still needs. */
x87h_mf:
    stp x30, x1, [sp, #-16]!
    aok_fp_end
    ldr x2, [_ip]
    mov x0, _cpu
    add x1, _pc, x2, lsr #32
    bl SYM(aok_x86_helper_fwait)
    ldp x30, x1, [sp], #16
    ret

#include "shared/x87-arith.S"
#include "shared/x87-stack.S"
x87_pop1_here
#include "shared/x87-reg.S"
x87_fcmov_all x87_fcmov, x87h_flag

/* ---- Memory forms -----------------------------------------------------------
 *
 * [word], after an ea gadget: the address is in _ea, and the word is a memory
 * gadget's (the insn's distance above, the log2 of the bytes below). The
 * shared code takes x5-x17 for itself, among them _ea and _addr, so the
 * address waits in x1, which it leaves alone.
 *
 * A load reads the operand through the softmmu path into aok_tmp, where the
 * shared code finds it: with other CPUs running, the barrier that keeps a
 * load before what follows it has to come after the load, and the shared
 * code's own load is of the copy. A store is converted into aok_tmp and
 * goes to the guest from x87m_wdone, before the stack is popped or the
 * status word written: a fault there leaves the insn to be run again with
 * nothing changed. x3 and x4, the converted value's registers, keep w7 and
 * w15 across it (_addr is x7).
 *
 * ARCH is q, or qmp for the gadgets with barriers.
 */
.macro x87m_gadget arch, name
    .ifc \arch,qmp
.gadget x87m_\name\()_mp
    .else
.gadget x87m_\name
    .endif
    mov x1, _ea
.endm
.macro x87m_wait arch
    x87_wait
.endm
.macro x87m_ret arch
    gret 1
.endm

.macro x87m_rprep arch, bits, id
    .if \bits == 80
    bl x87h_ld80
    ld_barrier
    add x9, _cpu, #AOK_X86_ENV_AOK_TMP
    .else
    mov _addr, x1
    x86_probe \bits, \id, TLBE_READ
    .if \bits == 16
    ldrh w10, [_addr]
    .endif
    .if \bits == 32
    ldr w10, [_addr]
    .endif
    .if \bits == 64
    ldr x10, [_addr]
    .endif
    ld_barrier
    str x10, [_cpu, #AOK_X86_ENV_AOK_TMP]
    add x9, _cpu, #AOK_X86_ENV_AOK_TMP
    .endif
.endm
.macro x87m_rtail arch, bits, id
    .if \bits != 80
    x86_slow_ld \bits, \id, 0
    .endif
.endm

.macro x87m_wprep arch, bits, id
    add x87_wp, _cpu, #AOK_X86_ENV_AOK_TMP
.endm
.macro x87m_wdone arch, bits, id
    .if \bits == 80
    st_barrier
    bl x87h_st80
    .else
    mov x3, x7
    mov x4, x15
    ldr x17, [_cpu, #AOK_X86_ENV_AOK_TMP]
    mov _addr, x1
    x86_probe \bits, \id, TLBE_WRITE
    st_barrier
    .if \bits == 16
    strh w17, [_addr]
    .endif
    .if \bits == 32
    str w17, [_addr]
    .endif
    .if \bits == 64
    str x17, [_addr]
    .endif
    mov x7, x3
    mov x15, x4
    .endif
.endm
.macro x87m_wtail arch, bits, id
    .if \bits != 80
    x86_slow_st \bits, \id, 0
    .endif
.endm

/*
 * The ten-byte operands (FLD and FSTP m80, FBLD, FBSTP) are two accesses,
 * made in C: x1 is the address, aok_tmp the bytes. The store keeps w7 and
 * w15 for what follows it.
 */
x87h_ld80:
    stp x30, x1, [sp, #-16]!
    aok_fp_end
    ldr x2, [_ip]
    mov x0, _cpu
    add x2, _pc, x2, lsr #32
    bl SYM(aok_x86_helper_ld80)
    ldp x30, x1, [sp], #16
    ret
x87h_st80:
    stp x30, x7, [sp, #-32]!
    stp x15, x1, [sp, #16]
    aok_fp_end
    ldr x2, [_ip]
    mov x0, _cpu
    add x2, _pc, x2, lsr #32
    bl SYM(aok_x86_helper_st80)
    ldp x15, x1, [sp, #16]
    ldp x30, x7, [sp], #32
    ret

#include "shared/x87-mem.S"

.macro x87h_forms arch
    x87m_arith_all \arch, f32, 32, x87_ld_f32
    x87m_arith_all \arch, f64, 64, x87_ld_f64
    x87m_arith_all \arch, i16, 16, x87_ld_int
    x87m_arith_all \arch, i32, 32, x87_ld_int
    x87m_loads \arch
    x87m_stores \arch
.endm
.set X86_MP, 0
x87h_forms q
.set X86_MP, 1
x87h_forms qmp
.set X86_MP, 0

#include "shared/x87-trans.S"

/* ---- The status and control words, read -------------------------------------
 *
 * [where in env the 16 bits go]: ax, or aok_tmp before a store. Neither
 * waits for a pending exception.
 */
.gadget x87h_fnstsw
    ldr x9, [_ip]
    x87_ld_fsw w8
    strh w8, [_cpu, x9]
    gret 1
.gadget x87h_fnstcw
    ldr x9, [_ip]
    ldrh w8, [_cpu, #AOK_X86_ENV_FPUC]
    strh w8, [_cpu, x9]
    gret 1
