/*
 * AOK gadgets for AArch64 guests: the ones shared with iSH-AOK.
 *
 * The integer gadgets and the bodies of the loads and stores are not written
 * here. shared/ holds iSH-AOK's own sources for them (jit/guest-arm64 there:
 * alu_spec.S, frag.h), copied by scripts/aok-gadgets-sync.sh and assembled as
 * they are: what is improved there arrives here with the next copy. Do not
 * edit them here.
 *
 * This file is the other half of the arrangement, the definitions a host of
 * those sources owes them (frag.h, "A second host"): the registers, how a
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

    .text

#include "shared/alu_spec.S"

/*
 * frag.h's bodies that are gadgets of files this host does not share, under
 * iSH-AOK's names for them (memory.S, math.S, simd_spec.S there).
 */
f_gadget mov_const, f_mov_const, _, _, _, _, _
f_gadget umov64, f_umov, ldr, x12, _, _, _
f_gadget umov32, f_umov, ldr, w12, _, _, _

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

/* Register offset: _rx (the index as it is), _rxs (sxtw), _rxu (uxtw). */
.irp ext, 0, 1, 2
f_gadget load8_rx\ext,      f_load_rx,  8, ldrb,  w17, \ext, _
f_gadget load16_rx\ext,     f_load_rx, 16, ldrh,  w17, \ext, _
f_gadget load32_rx\ext,     f_load_rx, 32, ldr,   w17, \ext, _
f_gadget load64_rx\ext,     f_load_rx, 64, ldr,   x17, \ext, _
f_gadget loads8_32_rx\ext,  f_load_rx,  8, ldrsb, w17, \ext, _
f_gadget loads8_64_rx\ext,  f_load_rx,  8, ldrsb, x17, \ext, _
f_gadget loads16_32_rx\ext, f_load_rx, 16, ldrsh, w17, \ext, _
f_gadget loads16_64_rx\ext, f_load_rx, 16, ldrsh, x17, \ext, _
f_gadget loads32_64_rx\ext, f_load_rx, 32, ldrsw, x17, \ext, _
f_gadget store8_rx\ext,     f_store_rx,  8, strb, w17, \ext, _
f_gadget store16_rx\ext,    f_store_rx, 16, strh, w17, \ext, _
f_gadget store32_rx\ext,    f_store_rx, 32, str,  w17, \ext, _
f_gadget store64_rx\ext,    f_store_rx, 64, str,  x17, \ext, _
.endr

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
