/*
 * AOK gadgets for RISC-V guests (RV64): loads and stores through the softmmu
 * TLB, branches and jumps, calls to C, and floating point. The integer
 * gadgets are in gadgets-shared.S.
 *
 * Operands are byte offsets into CPURISCVState, so one gadget serves every
 * register.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "accel/tcg/aok-asm.h"

    .text

/* ---- Integer arithmetic ------------------------------------------------- */

/*
 * Not here: gadgets-shared.S assembles iSH-AOK's own sources for the integer
 * gadgets (add_rr ... czero_nez_rr, mov_const, addi) and their fused pairs.
 * What follows is what this front end does its own way: anything that leaves
 * the stream, reaches guest memory, or computes in floating point.
 */

// x9=rd_off, x10=rs1 value, x11=rs2 value/imm; result in x10.
.macro alu_head
    ldr x9, [_ip]
    ldr x10, [_ip, #8]
    ldr x11, [_ip, #16]
    ldr x10, [_cpu, x10]
.endm
.macro alu_rr_head
    alu_head
    ldr x11, [_cpu, x11]
.endm
.macro alu_tail
    str x10, [_cpu, x9]
    gret 3
.endm

/* ---- Constants ---------------------------------------------------------- */

/* [rd offset][delta]: rd = entry pc + delta (auipc, and the link of a jal) */
.gadget rv_pcrel
    ldp x9, x10, [_ip]
    add x10, _pc, x10
    str x10, [_cpu, x9]
    gret 2

/*
 * [function][pc delta][insn] -- an insn done in C: function(env, pc, insn).
 * It finds its operands in the insn and env, and may raise an exception.
 */
.gadget rv_call
    aok_fp_end
    ldp x9, x1, [_ip]
    ldr x2, [_ip, #16]
    mov x0, _cpu
    add x1, _pc, x1
    blr x9
    gret 3

/*
 * The same, for an insn after which the TB must end in the main loop (a CSR
 * access: interrupts may now be enabled, the TB flags different). The
 * function has set env->pc.
 */
.gadget rv_call_exit
    aok_fp_end
    ldp x9, x1, [_ip]
    ldr x2, [_ip, #16]
    mov x0, _cpu
    add x1, _pc, x1
    blr x9
    mov x0, #0
    b SYM(aok_exit)

/* fence: a full barrier, as TCG's tcg_gen_mb(TCG_MO_ALL | TCG_BAR_SC) */
.gadget rv_fence
    dmb ish
    gret

/* ---- Loads, stores and branches -------------------------------------------
 *
 * Not here either: their bodies are iSH-AOK's too (gadgets-shared.S), and
 * what is this front end's about them -- the softmmu fast path and its slow
 * path, how a TB is left -- is the set of macros that file gives those
 * bodies.
 */

/* ---- Indirect jumps ------------------------------------------------------ */

/*
 * jalr: [rd offset][rs1 offset][imm][link delta]. The target is computed
 * from rs1 before the link is written, since rd may be rs1. Leaves env->pc
 * set, and the target in x10.
 */
.macro rv_jalr_body
    ldp x9, x10, [_ip]
    ldp x11, x12, [_ip, #16]
    ldr x10, [_cpu, x10]
    add x12, _pc, x12
    add x10, x10, x11
    bic x10, x10, #1
    str x12, [_cpu, x9]
    str x10, [_pcp]
.endm

/* For a TB that may not look its successor up: the stream exits next. */
.gadget rv_jalr
    rv_jalr_body
    gret 4

/*
 * The jalr that looks its target up is gadgets-shared.S's jalr_cached (the
 * name iSH-AOK's pairs know it by): it ends at aok_rv_lookup_pc below.
 */

/*
 * [flags | cflags << 32][cs_base] -- aok_gadget_lookup with tb_lookup()'s
 * first step done here: the TB for env->pc is usually in cpu->tb_jmp_cache,
 * in the entry tb_jmp_cache_hash_func(pc) names or in its partner. It is the
 * next TB if it is for this pc, has this TB's cs_base, flags and cflags
 * (which nothing a stream executes can have changed, and which an
 * invalidated TB no longer has), and is a stream. Anything else, and any
 * breakpoint at all, is aok_lookup_tb_ptr's to sort out.
 *
 * The constants are tb-hash.h's for a 4 KiB page and a 2^14-entry cache;
 * cpu-exec.c holds the build-time checks of the layout.
 */
.gadget rv_lookup
    ldr x10, [_pcp]
    /* (entered here with env->pc in x10 and _ip at the two operands) */
    .globl SYM(aok_rv_lookup_pc)
SYM(aok_rv_lookup_pc):
    ldr x11, [_bps]
    eor x12, x10, x10, lsr #5
    cbnz x11, 3f
    lsr x13, x12, #5
    and x12, x12, #0x7f
    and x13, x13, #0x3f80
    orr x12, x12, x13               /* the hash */
    add x13, _jc, x12, lsl #4
    ldp x14, x15, [x13, #16]        /* tb, pc */
    cmp x15, x10
    b.ne 2f
1:  cbz x14, 3f
    ldp x15, x16, [x14, #8]         /* cs_base, flags | cflags << 32 */
    ldp x11, x12, [_ip]
    ldrb w17, [x14, #28]            /* aok */
    cmp x16, x11
    ccmp x15, x12, #0, eq
    b.ne 3f
    cbz w17, 3f
    /* A jump between streams, as aok_goto_tail makes it. */
    ldr w11, [_exitreq]
    ldr _ip, [x14, #32]             /* tc.ptr */
    mov _pc, x10
    tbnz w11, #31, 4f
    gret AOK_ENTER_WORDS
2:  eor x12, x12, #1                /* the other way */
    add x13, _jc, x12, lsl #4
    ldp x14, x15, [x13, #16]
    cmp x15, x10
    b.eq 1b
3:  b SYM(aok_lookup_slow)
4:  b SYM(aok_exit_requested)

/* ---- Double-precision arithmetic on the host's FP unit --------------------
 *
 * Stream: [gadget][rd offset][rs1 offset][rs2 offset][pc delta][insn], and one
 * more register offset for the fused multiply-adds. Each of these is also
 * aok_rv_helper_fp's, softfloat's: the gadget does the cases where the host
 * gives softfloat's answer, flags included, and calls that for the rest.
 *
 * What differs between AArch64 and RISC-V, and what is done about it:
 *
 *   Rounding. The host rounds to nearest even, and QEMU never changes that.
 *   _fpok says the guest's frm asks for the same; it is found when a stream
 *   first uses the FP unit, and nothing can change frm without a call to C,
 *   which ends that use (aok_fp_end). When it is clear, softfloat.
 *
 *   NaN results. RISC-V produces one canonical NaN; AArch64 without FPCR.DN
 *   propagates an operand's. A result that is a NaN is replaced. The invalid
 *   flag is raised by the host in the same cases.
 *
 *   Underflow. RISC-V detects tininess after rounding and AArch64 before, so
 *   the host's underflow flag is never used (riscv_aok_fold_fpsr drops it).
 *   Underflow needs an inexact result that was below the smallest normal
 *   before it was rounded to the format: one with a zero exponent, or the
 *   smallest normal itself, which a tiny value can round up to. Sums and
 *   differences that small are exact. For the rest, such a result goes to
 *   softfloat unless an operand shows it is an exact zero.
 *
 *   Flags. The host's FPSR collects the others; see aok_fp_end.
 */

/* Leave this insn to softfloat: \n is the gadget's operand count. */
.macro rv_fp_soft n
    aok_fp_end
    ldp x1, x2, [_ip, #((\n - 2) * 8)]
    mov x0, _cpu
    add x1, _pc, x1
    bl SYM(aok_rv_helper_fp)
    gret \n
.endm

/* The stream's first use of the FP unit since it last called C. */
.macro rv_fp_begin again
    mov x0, _cpu
    bl SYM(aok_rv_fp_begin)
    mov _fpok, x0
    mov _fpact, #1
    b \again
.endm

/*
 * x12 = the result's bits. Leaves by 5f when its exponent is all ones or
 * all zeros, with w13 = 0x7fe for the former.
 */
.macro rv_fp_classify
    ubfx x13, x12, #52, #11
    sub w13, w13, #1
    cmp w13, #0x7fd
    b.hi 5f
.endm

/*
 * After rv_fp_classify, for what can underflow: the smallest normal, of
 * either sign, is \soft's too.
 */
.macro rv_fp_min_normal soft
    cbnz w13, 1f
    lsl x14, x12, #12
    cbz x14, \soft
.endm

/* At 5: an infinity is stored as it is, a NaN as the canonical one. */
.macro rv_fp_inf_nan zero
    cmp w13, #0x7fe
    b.ne \zero
    lsl x14, x12, #12
    cbz x14, 1b
    mov x12, #0x7ff8000000000000
    b 1b
.endm

.macro rv_fp_bin name, insn, zero
.gadget rv_f\name\()_d
0:  cbz _fpact, 8f
    cbz _fpok, 7f
    ldp x9, x10, [_ip]
    ldr x11, [_ip, #16]
    ldr d16, [_cpu, x10]
    ldr d17, [_cpu, x11]
    \insn d18, d16, d17
    fmov x12, d18
    rv_fp_classify
.ifnc \zero, exact
    rv_fp_min_normal 7f
.endif
1:  str x12, [_cpu, x9]
    gret 5
5:  rv_fp_inf_nan 6f
6:
.ifc \zero, exact               /* a sum that small is exact */
    b 1b
.endif
.ifc \zero, mul                 /* exact if either factor is zero */
    fcmp d16, #0.0
    b.eq 1b
    fcmp d17, #0.0
    b.eq 1b
.endif
.ifc \zero, div                 /* exact if the dividend is zero */
    fcmp d16, #0.0
    b.eq 1b
.endif
7:  rv_fp_soft 5
8:  rv_fp_begin 0b
.endm

rv_fp_bin add, fadd, exact
rv_fp_bin sub, fsub, exact
rv_fp_bin mul, fmul, mul
rv_fp_bin div, fdiv, div

/* The square root of a number is never subnormal. */
.gadget rv_fsqrt_d
0:  cbz _fpact, 8f
    cbz _fpok, 7f
    ldp x9, x10, [_ip]
    ldr d16, [_cpu, x10]
    fsqrt d18, d16
    fmov x12, d18
    rv_fp_classify
1:  str x12, [_cpu, x9]
    gret 5
5:  rv_fp_inf_nan 1b
7:  rv_fp_soft 5
8:  rv_fp_begin 0b

/*
 * [rd][rs1][rs2][rs3][pc delta][insn]. RISC-V names these by the product's
 * sign and AArch64 by the addend's: fmsub is rs1*rs2 - rs3, AArch64's fnmsub.
 */
.macro rv_fp_fma name, insn
.gadget rv_\name\()_d
0:  cbz _fpact, 8f
    cbz _fpok, 7f
    ldp x9, x10, [_ip]
    ldp x11, x14, [_ip, #16]
    ldr d16, [_cpu, x10]
    ldr d17, [_cpu, x11]
    ldr d19, [_cpu, x14]
    \insn d18, d16, d17, d19
    fmov x12, d18
    rv_fp_classify
    rv_fp_min_normal 7f
1:  str x12, [_cpu, x9]
    gret 6
5:  rv_fp_inf_nan 7f
7:  rv_fp_soft 6
8:  rv_fp_begin 0b
.endm

rv_fp_fma fmadd, fmadd
rv_fp_fma fmsub, fnmsub
rv_fp_fma fnmsub, fmsub
rv_fp_fma fnmadd, fnmadd

/*
 * Comparisons: no rounding, and the invalid flag as the host raises it --
 * feq is quiet (fcmp), flt and fle signal on any NaN (fcmpe).
 */
.macro rv_fp_cmp name, insn, cond
.gadget rv_f\name\()_d
0:  cbz _fpact, 8f
    ldp x9, x10, [_ip]
    ldr x11, [_ip, #16]
    ldr d16, [_cpu, x10]
    ldr d17, [_cpu, x11]
    \insn d16, d17
    cset x12, \cond
    str x12, [_cpu, x9]
    gret 5
8:  rv_fp_begin 0b
.endm

rv_fp_cmp eq, fcmp, eq
rv_fp_cmp lt, fcmpe, mi
rv_fp_cmp le, fcmpe, ls

/*
 * To an integer. Both saturate out of range and raise invalid, not inexact;
 * a NaN converts to the largest value in RISC-V and to zero in AArch64. The
 * _rtz ones are a static round-towards-zero, C's cast; the _dyn ones round
 * as frm says, which must be the host's way.
 */
.macro rv_fp_toint name, insn, reg, nan, sext, dyn
.gadget rv_fcvt_\name
0:  cbz _fpact, 8f
.ifc \dyn, dyn
    cbz _fpok, 7f
.endif
    ldp x9, x10, [_ip]
    ldr d16, [_cpu, x10]
    \insn \reg\()12, d16
    fcmp d16, d16
    b.vs 5f
.ifc \sext, sext
    sxtw x12, w12
.endif
1:  str x12, [_cpu, x9]
    gret 5
5:  mov x12, #\nan
    b 1b
.ifc \dyn, dyn
7:  rv_fp_soft 5
.endif
8:  rv_fp_begin 0b
.endm

rv_fp_toint w_d_rtz,  fcvtzs, w, 0x7fffffff, sext, rtz
rv_fp_toint wu_d_rtz, fcvtzu, w, -1, sext, rtz
rv_fp_toint l_d_rtz,  fcvtzs, x, 0x7fffffffffffffff, no, rtz
rv_fp_toint lu_d_rtz, fcvtzu, x, -1, no, rtz
rv_fp_toint w_d_dyn,  fcvtns, w, 0x7fffffff, sext, dyn
rv_fp_toint wu_d_dyn, fcvtnu, w, -1, sext, dyn
rv_fp_toint l_d_dyn,  fcvtns, x, 0x7fffffffffffffff, no, dyn
rv_fp_toint lu_d_dyn, fcvtnu, x, -1, no, dyn

/* From an integer, rounding as frm says: exact from 32 bits, not from 64. */
.macro rv_fp_fromint name, insn, reg
.gadget rv_fcvt_d_\name
0:  cbz _fpact, 8f
    cbz _fpok, 7f
    ldp x9, x10, [_ip]
    ldr x12, [_cpu, x10]
    \insn d18, \reg\()12
    str d18, [_cpu, x9]
    gret 5
7:  rv_fp_soft 5
8:  rv_fp_begin 0b
.endm

rv_fp_fromint w, scvtf, w
rv_fp_fromint wu, ucvtf, w
rv_fp_fromint l, scvtf, x
rv_fp_fromint lu, ucvtf, x

/* Sign injection is on the bits alone: [rd][rs1][rs2], no flags, no NaN rule. */
.gadget rv_fsgnj_d
    alu_rr_head
    and x11, x11, #0x8000000000000000
    and x10, x10, #0x7fffffffffffffff
    orr x10, x10, x11
    alu_tail
.gadget rv_fsgnjn_d
    alu_rr_head
    mvn x11, x11
    and x11, x11, #0x8000000000000000
    and x10, x10, #0x7fffffffffffffff
    orr x10, x10, x11
    alu_tail
.gadget rv_fsgnjx_d
    alu_rr_head
    and x11, x11, #0x8000000000000000
    eor x10, x10, x11
    alu_tail
