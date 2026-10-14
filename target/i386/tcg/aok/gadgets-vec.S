/*
 * AOK gadgets for x86 vector instructions: the VEX ones (AVX, AVX2, FMA3,
 * F16C, BMI1/2 and the opmask instructions), as iSH-AOK computes them.
 *
 * vec/vex.inc is iSH-AOK's frames for them and vec/bodies.inc the bodies
 * they expand, what an operation computes on 128 bits, exact to x86: its
 * NaNs, DAZ and FTZ, DE, and tininess after rounding (vec/bodies.inc's
 * head). They were taken from iSH-AOK on 2026-10-14 and are this tree's own
 * since. This file is what a host gives them, and the loads and stores of
 * their memory operands:
 *
 *   The state. A frame finds register r's 128-bit quarter q by name
 *   (CPU_xmm, CPU_ymm_hi, CPU_zmm_hi) and stride; QEMU keeps a register as
 *   one 64-byte ZMMReg, so each quarter is 16 bytes past the one before and
 *   the stride is 64 (vex.inc's vex_addr). MXCSR is env->mxcsr. The general
 *   registers are env->regs, as their numbers say.
 *
 *   A memory operand. The translator puts it in VEX_STAGE (env->aok_vstage)
 *   with one of the loads below before the frame, and a frame whose result
 *   goes to memory leaves it in a register or the stage for a store after:
 *   the softmmu fast path for an access inside a page, and C for the rest
 *   (aok_x86_helper_vldn, _vstn and _vprobe), which faults before anything
 *   is changed.
 *
 *   The FP environment. A frame of the floating-point kind (VEX_FP set
 *   where it is defined) computes on the host's FP unit with FPCR's rounding
 *   mode MXCSR's (aok_x86_fp_begin installs it when a stream first uses the
 *   unit), and what the host raised is folded into MXCSR's flags before the
 *   gadget dispatches; the double gadgets of gadgets.S leave only inexact in
 *   FPSR, which the first frame after them folds too.
 *
 *   The flags. A frame that sets EFLAGS does so as QEMU's CC_OP_EFLAGS has
 *   them, all six in cc_src (x86_vflags).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define AOK_ASM_OWN_GADGET
#include "accel/tcg/aok-asm.h"
#include "aok-i386-asm.h"

/* The state, under the names iSH-AOK's sources know it by. */
#define CPU_xmm         AOK_X86_ENV_XMM
#define CPU_ymm_hi      (AOK_X86_ENV_XMM + 16)
#define CPU_zmm_hi      (AOK_X86_ENV_XMM + 32)
#define CPU_mxcsr       AOK_X86_ENV_MXCSR
#define CPU_amd64_regs  AOK_X86_ENV_REGS
#define CPU_avx512_k    AOK_X86_ENV_OPMASK
#define VEX_STAGE       AOK_X86_ENV_VSTAGE
#define VEX_MASK        (AOK_X86_ENV_VSTAGE + 64)

_addr   .req x7
_ea     .req x6

/*
 * The FP environment of a floating-point frame. On entry: the stream's
 * first use of the unit gives FPCR MXCSR's rounding (a call to C, before the
 * frame has read anything), and an inexact some double gadget left in FPSR
 * is MXCSR's PE now; FPSR is then clear, so on the way out it holds exactly
 * what this frame raised, which goes to MXCSR's flags: IOC IE, DZC ZE, OFC
 * OE, UFC UE, IXC PE, IDC DE.
 */
.macro vfp_enter
    cbnz _fpact, .Lvfp_on\@
    mov x0, _cpu
    bl SYM(aok_x86_fp_begin)
    mov _fpok, x0
    mov _fpact, #1
.Lvfp_on\@:
    mrs x9, fpsr
    cbz x9, .Lvfp_clean\@
    tbz x9, #4, .Lvfp_clear\@
    ldr w10, [_cpu, #CPU_mxcsr]
    orr w10, w10, #0x20
    str w10, [_cpu, #CPU_mxcsr]
.Lvfp_clear\@:
    msr fpsr, xzr
.Lvfp_clean\@:
.endm
.macro vfp_leave
    mrs x9, fpsr
    cbz x9, .Lvfp_none\@
    and w10, w9, #1
    and w11, w9, #0x1e
    orr w10, w10, w11, lsl #1
    ubfx w11, w9, #7, #1
    orr w10, w10, w11, lsl #1
    ldr w11, [_cpu, #CPU_mxcsr]
    orr w11, w11, w10
    str w11, [_cpu, #CPU_mxcsr]
    msr fpsr, xzr
.Lvfp_none\@:
.endm

/*
 * A gadget, and its end. While VEX_FP is set (around the floating-point
 * frames in vex.inc) both see to the FP environment.
 */
.set VEX_FP, 0
.macro .gadget name
    .balign 16
    .globl SYM(aok_gadget_x86_\name)
SYM(aok_gadget_x86_\name):
    .if VEX_FP
    vfp_enter
    .endif
.endm
.purgem gret
.macro gret pop=0
    .if VEX_FP
    vfp_leave
    .endif
    ldr x9, [_ip, #(\pop * 8)]
    add _ip, _ip, #(\pop * 8 + 8)
    br x9
.endm
.macro gret_ahead
    ldr x9, [_ip, #-8]
    br x9
.endm

/* EFLAGS's six arithmetic flags, in w\reg at their places, as CC_OP_EFLAGS has them. */
.macro x86_vflags reg
    str x\reg, [_cpu, #AOK_X86_ENV_CC_SRC]
    str wzr, [_cpu, #AOK_X86_ENV_CC_OP]
.endm

    .text

#include "vec/bodies.inc"
#include "vec/vex.inc"

/* ---- Memory operands -----------------------------------------------------------
 *
 * As gadgets.S's loads and stores: the operand's form (bd, b3, ea) and the
 * host's word last, _ip past the next gadget by the time the access is
 * made. The fast path is one compare for an aligned access and a second
 * chance for an unaligned one inside its page; anything else is C's. An
 * operand that must be aligned (the "a" gadgets) has no second chance, and
 * C raises its #GP.
 */
#define TLB_FOLD        8
#define TLB_SHIFT       7
#define TLBE_READ       0
#define TLBE_WRITE      8
#define TLBE_ADDEND     24

.set X86_MP, 0
.macro ld_barrier
    .if X86_MP
    dmb ishld
    .endif
.endm
.macro st_barrier
    .if X86_MP
    dmb ishst
    .endif
.endm

.macro x86_probe size, id, tag
    ldp x9, x10, [_tlb]
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
    b.ne miss_\id
    add _addr, _addr, x10
back_\id:
.endm
.macro x86_unaligned size, id
    .if \size > 8
    and x9, _addr, #0xfff
    cmp x9, #(0x1000 - \size / 8)
    b.hi 1f
    tst _addr, #(\size / 8 - 1)
    b.eq 1f
    and x9, _addr, #0xfffffffffffff000
    cmp x11, x9
    b.ne 1f
    add _addr, _addr, x10
    b back_\id
1:
    .endif
.endm
.macro x86_call_slow fn, arg, woff=-16
    stp x1, x2, [sp, #-64]!
    stp x3, x4, [sp, #16]
    stp x5, x6, [sp, #32]
    stp x8, x17, [sp, #48]
    mov x4, \arg
    aok_fp_end
    ldr x3, [_ip, #\woff]
    mov x0, _cpu
    mov x1, _addr
    add x2, _pc, x3, lsr #32
    and x3, x3, #0xffffffff
    bl SYM(\fn)
    ldp x3, x4, [sp, #16]
    ldp x5, x6, [sp, #32]
    ldp x8, x17, [sp, #48]
    ldp x1, x2, [sp], #64
.endm
.macro mem_begin form, n
    .ifc \form, bd
    ldp x9, x10, [_ip, #(8 * \n)]
    add _ip, _ip, #(8 * (\n + 4))
    ldr x9, [_cpu, x9]
    add _addr, x9, x10
    .endif
    .ifc \form, b3
    ldp x9, x10, [_ip, #(8 * \n)]
    add _ip, _ip, #(8 * (\n + 4))
    ldr w9, [_cpu, x9]
    add w7, w9, w10
    .endif
    .ifc \form, ea
    add _ip, _ip, #(8 * (\n + 2))
    mov _addr, _ea
    .endif
.endm

/*
 * N bytes to VEX_STAGE, the rest of its first sixteen cleared:
 * [base][displacement][word] (or the ea gadget's address and [word]).
 * Sixteen bytes or fewer come back through the frame's scratch words as
 * gadgets.S's loads do; 32 and 64 are written to the stage by C.
 */
.macro vst_load bytes, from
    .if \bytes == 64
    ldp q0, q1, [\from]
    ldp q2, q3, [\from, #32]
    .elseif \bytes == 32
    ldp q0, q1, [\from]
    .elseif \bytes == 16
    ldr q0, [\from]
    .elseif \bytes == 8
    ldr d0, [\from]
    .elseif \bytes == 4
    ldr s0, [\from]
    .elseif \bytes == 2
    ldr h0, [\from]
    .else
    ldr b0, [\from]
    .endif
.endm
.macro vst_put bytes, to
    .if \bytes == 64
    stp q0, q1, [\to]
    stp q2, q3, [\to, #32]
    .elseif \bytes == 32
    stp q0, q1, [\to]
    .elseif \bytes == 16
    str q0, [\to]
    .elseif \bytes == 8
    str d0, [\to]
    .elseif \bytes == 4
    str s0, [\to]
    .elseif \bytes == 2
    str h0, [\to]
    .else
    str b0, [\to]
    .endif
.endm
.macro g_vldst name, bytes, form, aligned
.gadget \name
    mem_begin \form, 0
    x86_probe (\bytes * 8), \name, TLBE_READ
    vst_load \bytes, _addr
    ld_barrier
    mov x9, #VEX_STAGE
    add x9, _cpu, x9
    .if \bytes >= 16
    vst_put \bytes, x9
    .else
    str q0, [x9]
    .endif
done_\name:
    gret_ahead
miss_\name:
    .if \aligned == 0
    x86_unaligned (\bytes * 8), \name
    .endif
    .if \bytes > 16
    mov x9, #VEX_STAGE
    add x9, _cpu, x9
    x86_call_slow aok_x86_helper_vldn, x9
    b done_\name
    .else
    add x9, x29, #AOK_FRAME_SCRATCH
    x86_call_slow aok_x86_helper_ld, x9
    add _addr, x29, #AOK_FRAME_SCRATCH
    b back_\name
    .endif
.endm

/*
 * N bytes from the state to memory: [source offset][base][displacement]
 * [word]. The source is a register (one ZMMReg's bytes from the offset) or
 * VEX_STAGE. Sixteen bytes and fewer go through the scratch words to
 * gadgets.S's helpers; 32 and 64 are C's from the source.
 */
.macro g_vststore name, bytes, form, aligned
.gadget \name
    ldr x8, [_ip]
    mem_begin \form, 1
    x86_probe (\bytes * 8), \name, TLBE_WRITE
    add x9, _cpu, x8
    vst_load \bytes, x9
    st_barrier
    vst_put \bytes, _addr
done_\name:
    gret_ahead
miss_\name:
    .if \aligned == 0
    x86_unaligned (\bytes * 8), \name
    .endif
    .if \bytes > 16
    add x9, _cpu, x8
    x86_call_slow aok_x86_helper_vstn, x9
    b done_\name
    .elseif \bytes == 16
    ldr q16, [_cpu, x8]
    stur q16, [x29, #AOK_FRAME_SCRATCH]
    add x9, x29, #AOK_FRAME_SCRATCH
    x86_call_slow aok_x86_helper_vst, x9
    b done_\name
    .else
    .if \bytes == 8
    ldr x17, [_cpu, x8]
    .elseif \bytes == 4
    ldr w17, [_cpu, x8]
    .elseif \bytes == 2
    ldrh w17, [_cpu, x8]
    .else
    ldrb w17, [_cpu, x8]
    .endif
    x86_call_slow aok_x86_helper_st, x17
    b done_\name
    .endif
.endm

/* Whether N bytes may be written, and nothing written: [base][displacement][word]. */
.macro g_vstprobe name, bytes, form
.gadget \name
    mem_begin \form, 0
    x86_probe (\bytes * 8), \name, TLBE_WRITE
done_\name:
    gret_ahead
miss_\name:
    x86_unaligned (\bytes * 8), \name
    x86_call_slow aok_x86_helper_vprobe, xzr
    b done_\name
.endm

.macro vec_mem_one form, n, sfx
g_vldst vld\n\()_\form\sfx, \n, \form, 0
g_vststore vst\n\()_\form\sfx, \n, \form, 0
g_vstprobe vwp\n\()_\form\sfx, \n, \form
.endm
.macro vec_mem_aligned form, n, sfx
g_vldst vld\n\()a_\form\sfx, \n, \form, 1
g_vststore vst\n\()a_\form\sfx, \n, \form, 1
.endm
.irp form, bd, b3, ea
.irp n, 1, 2, 4, 8, 16, 32, 64
vec_mem_one \form, \n
.endr
.irp n, 16, 32, 64
vec_mem_aligned \form, \n
.endr
.endr
.set X86_MP, 1
.irp form, bd, b3, ea
.irp n, 1, 2, 4, 8, 16, 32, 64
vec_mem_one \form, \n, _mp
.endr
.irp n, 16, 32, 64
vec_mem_aligned \form, \n, _mp
.endr
.endr
.set X86_MP, 0
