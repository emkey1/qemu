/*
 * AOK gadgets for AArch64 guests: the ones taken from iSH-AOK.
 *
 * The integer gadgets, the bodies of the loads, stores and branches, and the
 * fused pairs are in shared/: iSH-AOK's sources for them (jit/guest-arm64
 * there: alu_spec.S, frag.h, pairs.h), taken on 2026-10-14 and this tree's
 * own since (shared/SOURCE).
 *
 * This file is what a host of those sources gives them (frag.h, "A second host"): the registers, how a
 * gadget begins and ends, where the guest's flags are, how guest memory is
 * reached.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define A64_GADGET_HOST qemu
#define AOK_ASM_OWN_GADGET
#include "accel/tcg/aok-asm.h"
#include "aok-arm-asm.h"


/*
 * The address of an access, and what a load or store body keeps across the
 * access. Nothing survives a call to C that is not saved around it (every
 * callee-saved register is aok_tb_exec's, aok-asm.h), so the slow paths
 * below save these, x8 and x17.
 */
_addr   .req x7
_fofs   .req x6
_fslot1 .req x5
_fslot2 .req x4
_fnewb  .req x3
_frn    .req x2
_fval2  .req x1

/* The dispatch of a body that has already moved _ip past the next word. */
.macro gret_ahead
    ldr x9, [_ip, #-8]
    br x9
.endm

/* (store_flags and load_flags, the flags a body asks for: aok-arm-asm.h) */

/* ---- Guest memory ----------------------------------------------------------
 *
 * Stream of a load or store: the body's own operands and then one word of
 * this host's, the insn in its low half and above it the insn's distance
 * from the TB's first.
 *
 * The softmmu fast path, as TCG's own backends inline it: index this TB's
 * fast table by the page number (folded, CPU_TLB_INDEX_FOLD), compare the
 * entry's tag with the address, and on a match the entry's addend turns the
 * guest address into a host one. The tag is compared with the address's page
 * AND its low alignment bits, so an aligned access to a page with no flags
 * set hits in one compare. Anything else leaves by the out-of-line half,
 * which sorts out what it is: an access that is only unaligned, inside its
 * page, is given the same entry's addend (A64 code makes many: memcpy's
 * overlapping heads and tails); MMIO, a watched or not-yet-dirty page, an
 * access across two pages and a real miss are cputlb's. A pair is two
 * accesses that may lie eight bytes off a doubleword, so it is tested for
 * crossing its page instead, and compared by page alone.
 *
 * cputlb does the whole access in C, and may raise a guest exception and not
 * return. It is told the insn's pc and opcode, which say everything about
 * the access but its address, and it stores the pc first, so the CPU state is
 * exact there with nothing to unwind. When it does return the body still
 * makes its access: of the frame's scratch words, where a load finds what C
 * read and where a store's write goes nowhere.
 */
#define TLB_FOLD        8       /* CPU_TLB_INDEX_FOLD */
#define TLB_SHIFT       7       /* TARGET_PAGE_BITS - CPU_TLB_ENTRY_BITS */
#define TLBE_READ       0
#define TLBE_WRITE      8
#define TLBE_ADDEND     24

/*
 * Two switches for the gadgets instantiated while they are set.
 * A64_SLOW_ONLY: no fast path at all, for an unprivileged access, which is
 * another mmu index's table. A64_ALIGNED: no second chance for an unaligned
 * address, for an ordered access, which must fault on one; cputlb is told.
 */
.set A64_SLOW_ONLY, 0
.set A64_ALIGNED, 0

.macro a64_tlb_probe size, id, tag
    .if A64_SLOW_ONLY
    b handle_miss_\id
    .else
    ldp x9, x10, [_tlb]         /* mask, table */
    eor x11, _addr, _addr, lsr #TLB_FOLD
    and x9, x9, x11, lsr #TLB_SHIFT
    add x10, x10, x9
    ldr x11, [x10, #\tag]
    ldr x10, [x10, #TLBE_ADDEND]
    .if \size > 64
    and x9, _addr, #0xfff
    cmp x9, #(0x1000 - \size / 8)
    b.hi handle_miss_\id
    and x9, _addr, #0xfffffffffffff000
    .elseif \size == 8
    and x9, _addr, #0xfffffffffffff000
    .else
    and x9, _addr, #(0xfffffffffffff000 | (\size / 8 - 1))
    .endif
    cmp x11, x9
    b.ne handle_miss_\id
    add _addr, _addr, x10
    .endif
back_\id:
.endm

.macro read_prep size, id, ahead=0
    a64_tlb_probe \size, \id, TLBE_READ
.endm
.macro write_prep size, id, ahead=0
    a64_tlb_probe \size, \id, TLBE_WRITE
.endm
.macro write_done size, id
.endm

/* Unaligned, but inside its page and the page plain RAM: the entry's addend. */
.macro a64_unaligned size, id
    .if \size > 8 && \size <= 64 && (A64_SLOW_ONLY + A64_ALIGNED) == 0
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

/* (_ip is \ahead bytes past the body's operands: the last is this host's) */
.macro a64_slow fn, id, ahead
    stp x1, x2, [sp, #-64]!
    stp x3, x4, [sp, #16]
    stp x5, x6, [sp, #32]
    stp x8, x17, [sp, #48]
    aok_fp_end                  /* (x14-x17 are its scratch) */
    ldr x2, [_ip, #-(\ahead + 8)]
    mov x0, _cpu
    mov x1, _addr
    and x3, x2, #0xffffffff     /* insn */
    add x2, _pc, x2, lsr #32    /* pc */
    add x4, x29, #AOK_FRAME_SCRATCH
    bl SYM(\fn)
    ldp x3, x4, [sp, #16]
    ldp x5, x6, [sp, #32]
    ldp x8, x17, [sp, #48]
    ldp x1, x2, [sp], #64
    add _addr, x29, #AOK_FRAME_SCRATCH
    b back_\id
.endm
.macro read_bullshit size, id, ahead=0
handle_miss_\id:
    a64_unaligned \size, \id
    a64_slow aok_a64_helper_ld, \id, \ahead
.endm
.macro write_bullshit size, id, ahead=0
handle_miss_\id:
    a64_unaligned \size, \id
    a64_slow aok_a64_helper_st, \id, \ahead
.endm

/* ---- Leaving a TB, as frag.h's branches do --------------------------------------
 *
 * A way out is two words, [pc delta][slot] (a64_leave), and a code address in
 * the stream is a delta from the TB's first insn, as everywhere here.
 */
#define F_WAY_WORDS 2
#define F_X0 (AOK_A64_ENV_X30 - 30 * 8)
.macro branch_leave off
    a64_leave \off
.endm
.macro pc_param reg
    add \reg, _pc, \reg
.endm

/*
 * The indirect branches, which are a host's own (frag.h), under iSH-AOK's
 * names so that its pairs can end in them. br and ret: [rn offset][tbi]
 * [link delta, unused][flags | cflags << 32][cs_base]; blr the same, the link
 * written. A pair's first half may hand the target over in a register (fn).
 */
.macro f_br_cached_body id, last, a1, a2, a3, a4, a5, fn=_, fm=_
    ldp x9, x11, [_ip]
    f_src 10, x9, \fn
    a64_tbi
    str x10, [_pcp]
    add _ip, _ip, #24
    b SYM(aok_a64_lookup_pc)
.endm
.macro f_br_cached_stub id, last, a1, a2, a3, a4, a5, fn=_, fm=_
.endm
.macro f_blr_cached_body id, last, a1, a2, a3, a4, a5, fn=_, fm=_
    ldp x9, x11, [_ip]
    ldr x13, [_ip, #16]
    f_src 10, x9, \fn
    add x13, _pc, x13
    a64_tbi
    str x13, [_cpu, #AOK_A64_ENV_X30]
    str x10, [_pcp]
    add _ip, _ip, #24
    b SYM(aok_a64_lookup_pc)
.endm
.macro f_blr_cached_stub id, last, a1, a2, a3, a4, a5, fn=_, fm=_
.endm

    .text

#include "shared/alu_spec.S"

/*
 * frag.h's bodies that are gadgets of files this host does not share, under
 * iSH-AOK's names for them (memory.S, math.S, simd_spec.S there).
 */
f_gadget mov_const, f_mov_const, _, _, _, _, _
f_gadget vspec_umov64, f_umov, ldr, x12, _, _, _
f_gadget vspec_umov32, f_umov, ldr, w12, _, _, _

f_gadget load8_fast,      f_load,  8, ldrb,  w17, _, _
f_gadget load16_fast,     f_load, 16, ldrh,  w17, _, _
f_gadget load32_fast,     f_load, 32, ldr,   w17, _, _
f_gadget load64_fast,     f_load, 64, ldr,   x17, _, _
f_gadget loads8_32_fast,  f_load,  8, ldrsb, w17, _, _
f_gadget loads8_64_fast,  f_load,  8, ldrsb, x17, _, _
f_gadget loads16_32_fast, f_load, 16, ldrsh, w17, _, _
f_gadget loads16_64_fast, f_load, 16, ldrsh, x17, _, _
f_gadget loads32_64_fast, f_load, 32, ldrsw, x17, _, _
f_gadget store8_fast,     f_store,  8, strb, w17, _, _
f_gadget store16_fast,    f_store, 16, strh, w17, _, _
f_gadget store32_fast,    f_store, 32, str,  w17, _, _
f_gadget store64_fast,    f_store, 64, str,  x17, _, _

/* Register offset, under iSH-AOK's names: _rxl (the index as it is), _rxs (sxtw), _rxu (uxtw). */
.macro a64_rx ext, sfx
f_gadget load8_rx\sfx,      f_load_rx,  8, ldrb,  w17, \ext, _
f_gadget load16_rx\sfx,     f_load_rx, 16, ldrh,  w17, \ext, _
f_gadget load32_rx\sfx,     f_load_rx, 32, ldr,   w17, \ext, _
f_gadget load64_rx\sfx,     f_load_rx, 64, ldr,   x17, \ext, _
f_gadget loads8_32_rx\sfx,  f_load_rx,  8, ldrsb, w17, \ext, _
f_gadget loads8_64_rx\sfx,  f_load_rx,  8, ldrsb, x17, \ext, _
f_gadget loads16_32_rx\sfx, f_load_rx, 16, ldrsh, w17, \ext, _
f_gadget loads16_64_rx\sfx, f_load_rx, 16, ldrsh, x17, \ext, _
f_gadget loads32_64_rx\sfx, f_load_rx, 32, ldrsw, x17, \ext, _
f_gadget store8_rx\sfx,     f_store_rx,  8, strb, w17, \ext, _
f_gadget store16_rx\sfx,    f_store_rx, 16, strh, w17, \ext, _
f_gadget store32_rx\sfx,    f_store_rx, 32, str,  w17, \ext, _
f_gadget store64_rx\sfx,    f_store_rx, 64, str,  x17, \ext, _
.endm
a64_rx 0, l
a64_rx 1, s
a64_rx 2, u

/* Pairs: offset, post-index, pre-index. (A pair of words is one 64-bit access.) */
f_gadget ldp64_fast, f_ldp, 128, 8, x17, _fval2, _
f_gadget ldp32_fast, f_ldp, 64, 4, w17, w1, _
f_gadget stp64_fast, f_stp, 128, 8, x17, _fval2, _
f_gadget stp32_fast, f_stp, 64, 4, w17, w1, _
f_gadget ldp64_post, f_ldp_wb, 128, 8, x17, _fval2, 0
f_gadget ldp64_pre,  f_ldp_wb, 128, 8, x17, _fval2, 1
f_gadget ldp32_post, f_ldp_wb, 64, 4, w17, w1, 0
f_gadget ldp32_pre,  f_ldp_wb, 64, 4, w17, w1, 1
f_gadget stp64_post, f_stp_wb, 128, 8, x17, _fval2, 0
f_gadget stp64_pre,  f_stp_wb, 128, 8, x17, _fval2, 1
f_gadget stp32_post, f_stp_wb, 64, 4, w17, w1, 0
f_gadget stp32_pre,  f_stp_wb, 64, 4, w17, w1, 1

/*
 * Loads and stores iSH-AOK has no body for (its own write-back and literal
 * loads are gadgets that read the register numbers at run time).
 *
 * A single register with write-back: [rt offset][rn offset][offset][word],
 * post-index (the access at the base) and pre-index (at base + offset). The
 * new base is written after the access, so a fault leaves rn as it was.
 */
.macro wb_load name, bits, ldinsn, reg, pre
.gadget \name
    ldp x8, _frn, [_ip]
    ldr _fofs, [_ip, #16]
    add _ip, _ip, #40
    ldr x10, [_cpu, _frn]
    add _fnewb, x10, _fofs
    .if \pre
    mov _addr, _fnewb
    .else
    mov _addr, x10
    .endif
    read_prep \bits, \name, 8
    \ldinsn \reg, [_addr]
    str x17, [_cpu, x8]
    str _fnewb, [_cpu, _frn]
    gret_ahead
    read_bullshit \bits, \name, 8
.endm
.macro wb_store name, bits, stinsn, reg, pre
.gadget \name
    ldp x8, _frn, [_ip]
    ldr _fofs, [_ip, #16]
    add _ip, _ip, #40
    ldr x10, [_cpu, _frn]
    ldr x17, [_cpu, x8]
    add _fnewb, x10, _fofs
    .if \pre
    mov _addr, _fnewb
    .else
    mov _addr, x10
    .endif
    write_prep \bits, \name, 8
    \stinsn \reg, [_addr]
    write_done \bits, \name
    str _fnewb, [_cpu, _frn]
    gret_ahead
    write_bullshit \bits, \name, 8
.endm
.irp pre, 0, 1
wb_load load8_wb\pre,      8, ldrb,  w17, \pre
wb_load load16_wb\pre,    16, ldrh,  w17, \pre
wb_load load32_wb\pre,    32, ldr,   w17, \pre
wb_load load64_wb\pre,    64, ldr,   x17, \pre
wb_load loads8_32_wb\pre,  8, ldrsb, w17, \pre
wb_load loads8_64_wb\pre,  8, ldrsb, x17, \pre
wb_load loads16_32_wb\pre, 16, ldrsh, w17, \pre
wb_load loads16_64_wb\pre, 16, ldrsh, x17, \pre
wb_load loads32_64_wb\pre, 32, ldrsw, x17, \pre
wb_store store8_wb\pre,    8, strb, w17, \pre
wb_store store16_wb\pre,  16, strh, w17, \pre
wb_store store32_wb\pre,  32, str,  w17, \pre
wb_store store64_wb\pre,  64, str,  x17, \pre
.endr

/* A literal: [rt offset][delta from the entry pc][unused][word] */
.macro lit_load name, bits, ldinsn, reg
.gadget \name
    ldp x8, x10, [_ip]
    add _ip, _ip, #40
    add _addr, _pc, x10
    read_prep \bits, \name, 8
    \ldinsn \reg, [_addr]
    str x17, [_cpu, x8]
    gret_ahead
    read_bullshit \bits, \name, 8
.endm
lit_load load32_lit, 32, ldr, w17
lit_load load64_lit, 64, ldr, x17
lit_load loads32_64_lit, 32, ldrsw, x17

/* Unprivileged (ldtr, sttr), where that is another translation regime's. */
.set A64_SLOW_ONLY, 1
f_gadget load8_user,      f_load,  8, ldrb,  w17, _, _
f_gadget load16_user,     f_load, 16, ldrh,  w17, _, _
f_gadget load32_user,     f_load, 32, ldr,   w17, _, _
f_gadget load64_user,     f_load, 64, ldr,   x17, _, _
f_gadget loads8_32_user,  f_load,  8, ldrsb, w17, _, _
f_gadget loads8_64_user,  f_load,  8, ldrsb, x17, _, _
f_gadget loads16_32_user, f_load, 16, ldrsh, w17, _, _
f_gadget loads16_64_user, f_load, 16, ldrsh, x17, _, _
f_gadget loads32_64_user, f_load, 32, ldrsw, x17, _, _
f_gadget store8_user,     f_store,  8, strb, w17, _, _
f_gadget store16_user,    f_store, 16, strh, w17, _, _
f_gadget store32_user,    f_store, 32, str,  w17, _, _
f_gadget store64_user,    f_store, 64, str,  x17, _, _
.set A64_SLOW_ONLY, 0

/* Ordered (ldar, stlr): the byte ones are the plain gadgets. */
.set A64_ALIGNED, 1
f_gadget load16_ord,  f_load, 16, ldrh, w17, _, _
f_gadget load32_ord,  f_load, 32, ldr,  w17, _, _
f_gadget load64_ord,  f_load, 64, ldr,  x17, _, _
f_gadget store16_ord, f_store, 16, strh, w17, _, _
f_gadget store32_ord, f_store, 32, str,  w17, _, _
f_gadget store64_ord, f_store, 64, str,  x17, _, _
.set A64_ALIGNED, 0

/* ---- FP and SIMD registers ----------------------------------------------------
 *
 * Loads and stores of B, H, S, D and Q registers, with the operands of the
 * X ones. A load writes the whole V register, the bytes it read zero-extended,
 * as do_fp_ld() does. cputlb's way makes the whole access, registers and all
 * (aok_a64_helper_vld and _vst): a pair of loads commits its first register
 * before the second can fault, as two do_fp_ld() do. The gadget then goes on
 * at done_NAME, with the write-back.
 */
.macro a64_vslow fn, id
    stp x1, x2, [sp, #-64]!
    stp x3, x4, [sp, #16]
    stp x5, x6, [sp, #32]
    stp x8, x17, [sp, #48]
    aok_fp_end
    ldr x2, [_ip, #-16]         /* the host's word: _ip is past the next gadget */
    mov x0, _cpu
    mov x1, _addr
    and x3, x2, #0xffffffff
    add x2, _pc, x2, lsr #32
    bl SYM(\fn)
    ldp x3, x4, [sp, #16]
    ldp x5, x6, [sp, #32]
    ldp x8, x17, [sp, #48]
    ldp x1, x2, [sp], #64
    b done_\id
.endm

/*
 * \mode: 0 [vt][rn][offset][word]; 1 the same, post-index; 2 pre-index;
 * 3, 4, 5 [vt][rn][rm][shift][word], rm as it is, sign- and zero-extended
 * from 32 bits; 6 a literal, [vt][delta from the entry pc][unused][word].
 */
.macro v_addr mode
    ldp x8, _frn, [_ip]
    .if \mode >= 3 && \mode <= 5
    ldp x11, x12, [_ip, #16]
    add _ip, _ip, #48
    ldr x10, [_cpu, _frn]
    ldr x11, [_cpu, x11]
    .if \mode == 4
    sxtw x11, w11
    .elseif \mode == 5
    mov w11, w11
    .endif
    lsl x11, x11, x12
    add _addr, x10, x11
    .elseif \mode == 6
    add _ip, _ip, #40
    add _addr, _pc, _frn
    .else
    ldr _fofs, [_ip, #16]
    add _ip, _ip, #40
    ldr x10, [_cpu, _frn]
    add _fnewb, x10, _fofs
    .if \mode == 1
    mov _addr, x10
    .else
    mov _addr, _fnewb
    .endif
    .endif
.endm
.macro v_tail name, mode
done_\name:
    .if \mode == 1 || \mode == 2
    str _fnewb, [_cpu, _frn]
    .endif
    gret_ahead
.endm

.macro v_load name, bits, reg, mode
.gadget \name
    v_addr \mode
    a64_tlb_probe \bits, \name, TLBE_READ
    ldr \reg, [_addr]
    str q0, [_cpu, x8]
    v_tail \name, \mode
handle_miss_\name:
    a64_unaligned \bits, \name
    a64_vslow aok_a64_helper_vld, \name
.endm
.macro v_store name, bits, reg, mode
.gadget \name
    v_addr \mode
    ldr q0, [_cpu, x8]
    a64_tlb_probe \bits, \name, TLBE_WRITE
    str \reg, [_addr]
    v_tail \name, \mode
handle_miss_\name:
    a64_unaligned \bits, \name
    a64_vslow aok_a64_helper_vst, \name
.endm
/* A pair: [vt | vt2 << 16][rn][offset][word] */
.macro v_ldp name, bytes, reg1, reg2, mode
.gadget \name
    v_addr \mode
    a64_tlb_probe (\bytes * 16), \name, TLBE_READ
    ldr \reg1, [_addr]
    ldr \reg2, [_addr, #\bytes]
    and x9, x8, #0xffff
    lsr x10, x8, #16
    str q0, [_cpu, x9]
    str q1, [_cpu, x10]
    v_tail \name, \mode
handle_miss_\name:
    a64_unaligned (\bytes * 16), \name
    a64_vslow aok_a64_helper_vld, \name
.endm
.macro v_stp name, bytes, reg1, reg2, mode
.gadget \name
    v_addr \mode
    and x9, x8, #0xffff
    lsr x10, x8, #16
    ldr q0, [_cpu, x9]
    ldr q1, [_cpu, x10]
    a64_tlb_probe (\bytes * 16), \name, TLBE_WRITE
    str \reg1, [_addr]
    str \reg2, [_addr, #\bytes]
    v_tail \name, \mode
handle_miss_\name:
    a64_unaligned (\bytes * 16), \name
    a64_vslow aok_a64_helper_vst, \name
.endm

/* vload8_0 ... vstore128_5: by size in bits and by mode */
.irp mode, 0, 1, 2, 3, 4, 5
v_load  vload8_\mode,     8, b0, \mode
v_load  vload16_\mode,   16, h0, \mode
v_load  vload32_\mode,   32, s0, \mode
v_load  vload64_\mode,   64, d0, \mode
v_load  vload128_\mode, 128, q0, \mode
v_store vstore8_\mode,     8, b0, \mode
v_store vstore16_\mode,   16, h0, \mode
v_store vstore32_\mode,   32, s0, \mode
v_store vstore64_\mode,   64, d0, \mode
v_store vstore128_\mode, 128, q0, \mode
.endr
v_load vload32_6,   32, s0, 6
v_load vload64_6,   64, d0, 6
v_load vload128_6, 128, q0, 6
.irp mode, 0, 1, 2
v_ldp vldp32_\mode,   4, s0, s1, \mode
v_ldp vldp64_\mode,   8, d0, d1, \mode
v_ldp vldp128_\mode, 16, q0, q1, \mode
v_stp vstp32_\mode,   4, s0, s1, \mode
v_stp vstp64_\mode,   8, d0, d1, \mode
v_stp vstp128_\mode, 16, q0, q1, \mode
.endr

/* ldpsw: [rt | rt2 << 16][rn][offset][word]; \mode 0 offset, 1 post-index, 2 pre-index */
.macro ldpsw_gadget name, mode
.gadget \name
    ldp x8, _frn, [_ip]
    ldr _fofs, [_ip, #16]
    add _ip, _ip, #40
    ldr x10, [_cpu, _frn]
    add _fnewb, x10, _fofs
    .if \mode == 1
    mov _addr, x10
    .else
    mov _addr, _fnewb
    .endif
    read_prep 64, \name, 8
    ldpsw x17, x12, [_addr]
    and x9, x8, #0xffff
    lsr x10, x8, #16
    str x17, [_cpu, x9]
    str x12, [_cpu, x10]
    .if \mode
    str _fnewb, [_cpu, _frn]
    .endif
    gret_ahead
    read_bullshit 64, \name, 8
.endm
ldpsw_gadget ldpsw_fast, 0
ldpsw_gadget ldpsw_post, 1
ldpsw_gadget ldpsw_pre, 2

/*
 * ld1 and st1 of one to four whole registers, which in a little-endian guest
 * are that many loads or stores of 8 or 16 bytes whatever the arrangement:
 * [vt | vt + 1 << 16 | ...][rn][post-index immediate][post-index register][word]
 * The base is written back as it is plus the two, each nothing where the
 * instruction has no post-index. Every other structure load and store is a
 * call (aok_a64_helper_struct), as is the slow path here.
 */
.macro v_struct name, n, bytes, reg0, reg1, reg2, reg3, load
.gadget \name
    ldp x8, _frn, [_ip]
    ldp _fofs, x11, [_ip, #16]
    add _ip, _ip, #48
    ldr x10, [_cpu, _frn]
    ldr x11, [_cpu, x11]
    add _fnewb, x10, _fofs
    add _fnewb, _fnewb, x11
    mov _addr, x10
    .if \load
    a64_tlb_probe (\n * \bytes * 8), \name, TLBE_READ
    ldr \reg0, [_addr]
    .if \n > 1
    ldr \reg1, [_addr, #\bytes]
    .endif
    .if \n > 2
    ldr \reg2, [_addr, #(2 * \bytes)]
    .endif
    .if \n > 3
    ldr \reg3, [_addr, #(3 * \bytes)]
    .endif
    and x9, x8, #0xffff
    str q0, [_cpu, x9]
    .if \n > 1
    ubfx x9, x8, #16, #16
    str q1, [_cpu, x9]
    .endif
    .if \n > 2
    ubfx x9, x8, #32, #16
    str q2, [_cpu, x9]
    .endif
    .if \n > 3
    lsr x9, x8, #48
    str q3, [_cpu, x9]
    .endif
    .else
    and x9, x8, #0xffff
    ldr q0, [_cpu, x9]
    .if \n > 1
    ubfx x9, x8, #16, #16
    ldr q1, [_cpu, x9]
    .endif
    .if \n > 2
    ubfx x9, x8, #32, #16
    ldr q2, [_cpu, x9]
    .endif
    .if \n > 3
    lsr x9, x8, #48
    ldr q3, [_cpu, x9]
    .endif
    a64_tlb_probe (\n * \bytes * 8), \name, TLBE_WRITE
    str \reg0, [_addr]
    .if \n > 1
    str \reg1, [_addr, #\bytes]
    .endif
    .if \n > 2
    str \reg2, [_addr, #(2 * \bytes)]
    .endif
    .if \n > 3
    str \reg3, [_addr, #(3 * \bytes)]
    .endif
    .endif
done_\name:
    str _fnewb, [_cpu, _frn]
    gret_ahead
handle_miss_\name:
    a64_unaligned (\n * \bytes * 8), \name
    a64_vslow aok_a64_helper_struct_slow, \name
.endm
.irp n, 1, 2, 3, 4
v_struct vld1_\n\()_q, \n, 16, q0, q1, q2, q3, 1
v_struct vld1_\n\()_d, \n, 8, d0, d1, d2, d3, 1
v_struct vst1_\n\()_q, \n, 16, q0, q1, q2, q3, 0
v_struct vst1_\n\()_d, \n, 8, d0, d1, d2, d3, 0
.endr

/* ---- Branches: frag.h's bodies, under iSH-AOK's names -------------------------- */
f_gadget b, f_b, _, _, _, _, _
f_gadget bl, f_bl, _, _, _, _, _
f_gadget br_cached, f_br_cached, _, _, _, _, _
f_gadget blr_cached, f_blr_cached, _, _, _, _, _
f_gadget ret_cached, f_br_cached, _, _, _, _, _
/* cbz, cbnz: [rt offset][taken way][other way]; _bk for a branch backwards */
.macro a64_cb name, reg, jmp, jmp_bk
    f_gadget \name, f_cb, \reg, \jmp, _, _, _
    f_gadget \name\()_bk, f_cb_bk, \reg, \jmp_bk, _, _, _
.endm
a64_cb cbz_x,  x9, cbz,  cbnz
a64_cb cbz_w,  w9, cbz,  cbnz
a64_cb cbnz_x, x9, cbnz, cbz
a64_cb cbnz_w, w9, cbnz, cbz
/* tbz, tbnz: [rt offset][bit mask][taken way][other way] */
.macro a64_tb name, jmp, jmp_bk
    f_gadget \name, f_tb, \jmp, _, _, _, _
    f_gadget \name\()_bk, f_tb_bk, \jmp_bk, _, _, _, _
.endm
a64_tb tb_z,  cbz,  cbnz
a64_tb tb_nz, cbnz, cbz
/*
 * b.cond: [taken way][other way], reloading the flags or (_nf) not; and a
 * cmp with the b.cond after it, one gadget: [rn][imm] or [rn | rm << 8],
 * then the two ways (register numbers: F_X0).
 */
.irp cc, CONDS
f_gadget bcond_\cc, f_bcond, \cc, _, _, _, _
f_gadget bcond_nf_\cc, f_bcond_nf, \cc, _, _, _, _
f_gadget fused_cmpi64_\cc, f_fused_cmpi, subs, xzr, x15, x11, \cc
f_gadget fused_cmpi32_\cc, f_fused_cmpi, subs, wzr, w15, w11, \cc
f_gadget fused_cmpr64_\cc, f_fused_cmpr, subs, xzr, x15, x13, \cc
f_gadget fused_cmpr32_\cc, f_fused_cmpr, subs, wzr, w15, w13, \cc
.endr

/*
 * ---- Fused pairs ------------------------------------------------------------------
 *
 * iSH-AOK's list (shared/pairs.h), less the pairs with a gadget this front end
 * does not have (shared/host-gadgets.h, which scripts/aok-host-gadgets.sh
 * writes by assembling this file without them).
 */
#include "shared/host-gadgets.h"
#define FUSE2(a, b) A64_HOST(HOST_##a, HOST_##b)(a, b)
#define A64_HOST(x, y) A64_HOST_(x, y)
#define A64_HOST_(x, y) A64_HOST_##x##y
#define A64_HOST_00(a, b)
#define A64_HOST_01(a, b)
#define A64_HOST_10(a, b)
#define A64_HOST_11(a, b) fuse2 a##__##b, R_##a, K_##b, F_##a, F_##b
#include "shared/pairs.h"
#undef FUSE2
