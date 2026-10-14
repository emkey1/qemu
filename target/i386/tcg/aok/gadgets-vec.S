/*
 * AOK gadgets for x86 vector instructions: the VEX ones (AVX, AVX2, FMA3,
 * F16C, BMI1/2 and the opmask instructions) and the EVEX ones (AVX-512 and
 * the extensions with it), as iSH-AOK computes them.
 *
 * vec/vex.inc and vec/evex.inc are iSH-AOK's frames for them and
 * vec/bodies.inc the bodies they expand, what an operation computes on 128
 * bits, exact to x86: its NaNs, DAZ and FTZ, DE, and tininess after
 * rounding (vec/bodies.inc's head). They were taken from iSH-AOK on
 * 2026-10-14 and are this tree's own since. This file is what a host gives
 * them, and the loads and stores of their memory operands:
 *
 *   The state. A frame finds register r's 128-bit quarter q by name
 *   (CPU_xmm, CPU_ymm_hi, CPU_zmm_hi) and stride; QEMU keeps a register as
 *   one 64-byte ZMMReg, so each quarter is 16 bytes past the one before and
 *   the stride is 64 (vex.inc's vex_addr, evex.inc's evx_qaddr). MXCSR is
 *   env->mxcsr, the opmask registers env->opmask_regs. The general
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
#include "vec/evex.inc"

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

/* ---- EVEX's memory operands -----------------------------------------------------
 *
 * Its loads and stores of whole operands are the ones above (the stores from
 * VEX_STAGE, where a frame with word bit 32 leaves its result). These are
 * the rest: a broadcast ({1toN}), an operand only some of whose elements
 * the opmask enables, and the gathers and scatters.
 *
 * vm_elems: x16 = the elements the opmask enables (the field at bit \ks of
 * the EVEX word in x8, the log2 of their size 4 bits up, in x15), w14 = the
 * operand's bytes: 16 << VL, or 1 << bits 59-61 with bit 58 (a narrowing
 * store's). Clobbers x9, x11.
 */
.macro vm_elems ks
    ubfx x9, x8, #\ks, #3
    mov x11, #CPU_avx512_k
    add x11, _cpu, x11
    ldr x16, [x11, x9, lsl #3]
    ubfx x15, x8, #(\ks + 4), #2
    ubfx w9, w8, #16, #2
    mov w14, #16
    lsl w14, w14, w9
    tbz x8, #58, 1f
    ubfx x9, x8, #59, #3
    mov w14, #1
    lsl w14, w14, w9
1:  lsr w9, w14, w15
    cmp w9, #64
    b.hs 2f
    mov x11, #1
    lsl x11, x11, x9
    sub x11, x11, #1
    and x16, x16, x11
2:
.endm

/* Compress (word bit 62): x16 its first popcount(x16) elements. Clobbers x9, v30. */
.macro vm_compress
    tbz x8, #62, 1f
    fmov d30, x16
    cnt v30.8b, v30.8b
    addv b30, v30.8b
    fmov w9, s30
    mov x16, #-1
    cmp w9, #64
    b.hs 1f
    mov x16, #1
    lsl x16, x16, x9
    sub x16, x16, #1
1:
.endm

/* An operand that must be aligned to its size (the host's word, bit 4) and is not: C's #GP. */
.macro vm_align id
    ldr x9, [_ip, #-16]
    tbz x9, #4, 1f
    sub w10, w14, #1
    tst _addr, x10
    b.ne slow_\id
1:
.endm

/* The operand inside one page, or C's. */
.macro vm_onepage id
    and x9, _addr, #0xfff
    add x9, x9, x14
    cmp x9, #0x1000
    b.hi slow_\id
.endm

/*
 * A broadcast: one element of 4 or 8 bytes over VEX_STAGE's 64. Masked
 * ([EVEX word] first): nothing read when the opmask enables no element, and
 * the stage as it was (the frame takes none of it).
 */
.macro g_vldb name, bytes, form, masked
.gadget \name
    .if \masked
    ldr x8, [_ip]
    mem_begin \form, 1
    vm_elems 18
    cbz x16, done_\name
    .else
    mem_begin \form, 0
    .endif
    x86_probe (\bytes * 8), \name, TLBE_READ
    .if \bytes == 4
    ld1r {v0.4s}, [_addr]
    .else
    ld1r {v0.2d}, [_addr]
    .endif
    ld_barrier
    mov x9, #VEX_STAGE
    add x9, _cpu, x9
    stp q0, q0, [x9]
    stp q0, q0, [x9, #32]
done_\name:
    gret_ahead
miss_\name:
    x86_unaligned (\bytes * 8), \name
    add x9, x29, #AOK_FRAME_SCRATCH
    x86_call_slow aok_x86_helper_ld, x9
    add _addr, x29, #AOK_FRAME_SCRATCH
    b back_\name
.endm

/*
 * A masked load to VEX_STAGE: [EVEX word][base][displacement][word]. Only
 * the elements the opmask enables may be read, so that a masked-off one may
 * lie on a page that is not there: inside one page, the whole operand when
 * any is enabled, nothing (and zeros) when none is; across two, or a TLB
 * miss, C's aok_x86_helper_vldm, page by page.
 */
.macro g_vldm name, form
.gadget \name
    ldr x8, [_ip]
    mem_begin \form, 1
    vm_elems 18
    vm_align \name
    cbz x16, zero_\name
    vm_onepage \name
    x86_probe 8, \name, TLBE_READ
    mov x9, #VEX_STAGE
    add x9, _cpu, x9
    cmp w14, #32
    b.lo 2f
    ldp q0, q1, [_addr]
    stp q0, q1, [x9]
    b.eq 3f
    ldp q2, q3, [_addr, #32]
    stp q2, q3, [x9, #32]
    b 3f
2:  ldr q0, [_addr]
    str q0, [x9]
3:  ld_barrier
done_\name:
    gret_ahead
zero_\name:
    mov x9, #VEX_STAGE
    add x9, _cpu, x9
    stp xzr, xzr, [x9]
    stp xzr, xzr, [x9, #16]
    stp xzr, xzr, [x9, #32]
    stp xzr, xzr, [x9, #48]
    b done_\name
miss_\name:
slow_\name:
    x86_call_slow aok_x86_helper_vldm, x8
    b done_\name
.endm

/*
 * A masked store from VEX_STAGE: [EVEX word][base][displacement][word].
 * Only the enabled elements are written (compress: the first popcount of
 * them); inside one page here, element by element, and otherwise C's
 * aok_x86_helper_vstm, which faults before it writes anything. With
 * \probe (vwpm), only the faults: for a frame that changes state (MXCSR)
 * before its store.
 */
.macro vm_store_loop name, ldr, str, reg, sh
\name:
    rbit x10, x16
    clz x10, x10
    \ldr \reg\()12, [x9, x10, lsl #\sh]
    \str \reg\()12, [_addr, x10, lsl #\sh]
    sub x10, x16, #1
    ands x16, x16, x10
    b.ne \name
.endm
.macro g_vstm name, form, probe=0
.gadget \name
    ldr x8, [_ip]
    mem_begin \form, 1
    vm_elems 40
    vm_align \name
    cbz x16, done_\name
    vm_onepage \name
    vm_compress
    x86_probe 8, \name, TLBE_WRITE
    .if \probe
    b done_\name
    .endif
    mov x9, #VEX_STAGE
    add x9, _cpu, x9
    st_barrier
    cmp w15, #1
    b.lo b_\name
    b.eq h_\name
    cmp w15, #2
    b.eq s_\name
    vm_store_loop d_\name, ldr, str, x, 3
    b done_\name
    vm_store_loop s_\name, ldr, str, w, 2
    b done_\name
    vm_store_loop h_\name, ldrh, strh, w, 1
    b done_\name
    vm_store_loop b_\name, ldrb, strb, w, 0
done_\name:
    gret_ahead
miss_\name:
slow_\name:
    .if \probe
    x86_call_slow aok_x86_helper_vwpm, x8
    .else
    x86_call_slow aok_x86_helper_vstm, x8
    .endif
    b done_\name
.endm

/*
 * Gathers and scatters: [EVEX word][base][displacement][word] (or the ea
 * gadget's address, without the index: that is the vector register), the
 * word's size the element's. EVEX word: [the data register (0-4) | the
 * index register (5-9) | scale (10-11) | qword data (12) | qword indices
 * (13) | VL (16-17) | opmask (18-20)]; n elements: the VL's, of the wider of
 * data and index. Restartable as x86's: each step takes the lowest element
 * the opmask still enables, moves it and clears its bit, so a fault leaves
 * the elements below it done and their bits clear, the rest as they were.
 * Only x1 (the base), x3 (the element) and x8 outlive a slow path: each
 * step finds its element again after it. Done: the opmask zeroed whole, and a gather's
 * destination past its elements.
 */
.macro evg_next                          /* w12 = the lowest element the opmask enables, or 64. Clobbers x14-x17 */
    ubfx w14, w8, #18, #3
    mov x16, #CPU_avx512_k
    add x16, _cpu, x16
    ldr x17, [x16, x14, lsl #3]
    ubfx w14, w8, #16, #2
    mov w15, #16
    lsl w15, w15, w14                    /* the VL's bytes */
    ubfx w14, w8, #12, #2
    cmp w14, #0
    cset w14, ne
    add w14, w14, #2
    lsr w15, w15, w14                    /* its elements (16 at most) */
    mov x14, #1
    lsl x14, x14, x15
    sub x14, x14, #1
    and x17, x17, x14
    rbit x17, x17
    clz x12, x17
.endm
/* \out = &element w12 of the register in the word's bits \field-(\field + 4), of 4 << word bit \szbit bytes. Clobbers x14-x17 */
.macro evg_eaddr out, field, szbit
    ubfx w17, w8, #\szbit, #1
    add w17, w17, #2
    lsl w17, w12, w17                    /* the element's byte */
    ubfx w14, w8, #\field, #5
    lsr w16, w17, #4
    evx_qaddr \out, w14, w16
    and w17, w17, #15
    add \out, \out, x17
.endm
.macro evg_index                         /* x13 = element w12's index, sign-extended, scaled. Clobbers x14-x17 */
    evg_eaddr x13, 5, 13
    tbnz w8, #13, 1f
    ldrsw x13, [x13]
    b 2f
1:  ldr x13, [x13]
2:  ubfx w14, w8, #10, #2
    lsl x13, x13, x14
.endm
.macro evg_clear                         /* the opmask's bit w12 cleared. Clobbers x13, x14, x16, x17 */
    ubfx w14, w8, #18, #3
    mov x16, #CPU_avx512_k
    add x16, _cpu, x16
    ldr x17, [x16, x14, lsl #3]
    mov x13, #1
    lsl x13, x13, x12
    bic x17, x17, x13
    str x17, [x16, x14, lsl #3]
.endm
.macro evg_put                           /* the data register's element w12 = x3, its bit cleared */
    evg_eaddr x13, 0, 12
    tbnz w8, #12, 1f
    str w3, [x13]
    b 2f
1:  str x3, [x13]
2:  evg_clear
.endm
.macro evg_get                           /* x3 = the data register's element w12 */
    evg_eaddr x13, 0, 12
    tbnz w8, #12, 1f
    ldr w3, [x13]
    b 2f
1:  ldr x3, [x13]
2:
.endm
.macro evg_finish scatter
    ubfx w14, w8, #18, #3
    mov x16, #CPU_avx512_k
    add x16, _cpu, x16
    str xzr, [x16, x14, lsl #3]
    .if \scatter == 0
    ubfx w14, w8, #16, #2
    mov w13, #16
    lsl w13, w13, w14                    /* the data's bytes: the VL's, */
    ubfx w14, w8, #12, #2
    cmp w14, #2
    b.ne 1f
    lsr w13, w13, #1                     /* or half for qword indices, dword data */
1:  cmp w13, #64
    b.hs 2f
    lsr w16, w13, #4
    and w17, w8, #31
    evx_qaddr x14, w17, w16
    and w17, w13, #15
    add x14, x14, x17
    str xzr, [x14]
    add w13, w13, #8
    b 1b
2:
    .endif
.endm

.macro g_vgs_slow name, n, scatter
miss_\name\()_\n:
    x86_unaligned (\n * 8), \name\()_\n
    .if \scatter
    x86_call_slow aok_x86_helper_st, x3
    b next_\name
    .else
    add x9, x29, #AOK_FRAME_SCRATCH
    x86_call_slow aok_x86_helper_ld, x9
    add _addr, x29, #AOK_FRAME_SCRATCH
    b back_\name\()_\n
    .endif
.endm
.macro g_vgs name, form, scatter
.gadget \name
    ldr x8, [_ip]
    mem_begin \form, 1
    mov x1, _addr
loop_\name:
    evg_next
    cmp w12, #64
    b.hs fin_\name
    evg_index
    add _addr, x1, x13
    .if \scatter
    evg_get
    tbnz w8, #12, q_\name
    x86_probe 32, \name\()_4, TLBE_WRITE
    st_barrier
    str w3, [_addr]
    b next_\name
q_\name:
    x86_probe 64, \name\()_8, TLBE_WRITE
    st_barrier
    str x3, [_addr]
next_\name:
    evg_next
    evg_clear
    b loop_\name
    .else
    tbnz w8, #12, q_\name
    x86_probe 32, \name\()_4, TLBE_READ
    ldr w3, [_addr]
    b got_\name
q_\name:
    x86_probe 64, \name\()_8, TLBE_READ
    ldr x3, [_addr]
got_\name:
    ld_barrier
    evg_next
    evg_put
    b loop_\name
    .endif
fin_\name:
    evg_finish \scatter
    gret_ahead
    g_vgs_slow \name, 4, \scatter
    g_vgs_slow \name, 8, \scatter
.endm

.macro evex_mem_one form, sfx
g_vldb vldb4_\form\sfx, 4, \form, 0
g_vldb vldb8_\form\sfx, 8, \form, 0
g_vldb vldbm4_\form\sfx, 4, \form, 1
g_vldb vldbm8_\form\sfx, 8, \form, 1
g_vldm vldm_\form\sfx, \form
g_vstm vstm_\form\sfx, \form
g_vstm vwpm_\form\sfx, \form, 1
g_vgs vgather_\form\sfx, \form, 0
g_vgs vscatter_\form\sfx, \form, 1
.endm
.irp form, bd, b3, ea
evex_mem_one \form
.endr
.set X86_MP, 1
.irp form, bd, b3, ea
evex_mem_one \form, _mp
.endr
.set X86_MP, 0
