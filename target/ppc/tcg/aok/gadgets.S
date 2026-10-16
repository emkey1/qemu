/*
 * AOK gadgets for 32-bit PowerPC guests (qemu-system-ppc): a big-endian
 * guest whose registers are 32 bits wide, on an AArch64 host.
 *
 * Operands are byte offsets into CPUPPCState, so one gadget serves every
 * register. The fields a gadget reaches by itself (the CR fields, XER's SO
 * and CA, LR, CTR) are at aok-ppc-asm.h's offsets. A guest value lives in
 * the w view of a host register, where a 32-bit result wraps as the guest's
 * does.
 *
 * Nothing here but the memory macros and the ways a TB is left is
 * particular to QEMU, so that a PowerPC guest in iSH-AOK can take the rest.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "accel/tcg/aok-asm.h"
#include "aok-ppc-asm.h"

    .text

/* ---- Integer arithmetic and logic ------------------------------------------
 *
 * Streams: [gadget][rD][rA][rB] (rr), [gadget][rD][rA][imm] (ri), and
 * [gadget][rD][rA] for the one-operand forms; each an offset into
 * CPUPPCState but the immediate. The logical ops write rA from rS and rB, and
 * take the same layout: [rA][rS][rB]. What a record form (Rc) adds is
 * ppc_cr0 after the gadget.
 *
 * XER[CA] is the host's carry flag between a load and a store of env->ca:
 * AArch64's adds/adcs set C as PowerPC sets CA, and subs/sbcs compute
 * b + ~a + C, which is subf's definition.
 */
.macro rr
    ldp x9, x10, [_ip]
    ldr x11, [_ip, #16]
    ldr w10, [_cpu, x10]
    ldr w11, [_cpu, x11]
.endm
.macro ri
    ldp x9, x10, [_ip]
    ldr x11, [_ip, #16]
    ldr w10, [_cpu, x10]
.endm
.macro r1
    ldp x9, x10, [_ip]
    ldr w10, [_cpu, x10]
.endm
.macro put
    str w10, [_cpu, x9]
    gret 3
.endm
.macro put1
    str w10, [_cpu, x9]
    gret 2
.endm
/* the carry-in: C = CA */
.macro ca_in
    ldr w12, [_cpu, #AOK_PPC_ENV_CA]
    cmp w12, #1
.endm
/* the carry-out: CA = C */
.macro ca_out
    cset w12, cs
    str w12, [_cpu, #AOK_PPC_ENV_CA]
.endm

/* [rD][imm]: li, lis */
.gadget ppc_li
    ldp x9, x10, [_ip]
    str w10, [_cpu, x9]
    gret 2

/* [dst][src]: mr, and the moves of LR, CTR and a CR field (mcrf) */
.gadget ppc_mov
    ldp x9, x10, [_ip]
    ldr w10, [_cpu, x10]
    str w10, [_cpu, x9]
    gret 2

.gadget ppc_add
    rr
    add w10, w10, w11
    put
.gadget ppc_addi
    ri
    add w10, w10, w11
    put
/* subf: rD = rB - rA */
.gadget ppc_subf
    rr
    sub w10, w11, w10
    put
.gadget ppc_neg
    r1
    neg w10, w10
    put1

.gadget ppc_addc
    rr
    adds w10, w10, w11
    ca_out
    put
.gadget ppc_addic
    ri
    adds w10, w10, w11
    ca_out
    put
.gadget ppc_adde
    rr
    ca_in
    adcs w10, w10, w11
    ca_out
    put
.gadget ppc_addme
    r1
    ca_in
    mov w11, #-1
    adcs w10, w10, w11
    ca_out
    put1
.gadget ppc_addze
    r1
    ca_in
    adcs w10, w10, wzr
    ca_out
    put1
/* subfc: rD = rB - rA, CA = rB >= rA (unsigned); subfic: imm - rA */
.gadget ppc_subfc
    rr
    subs w10, w11, w10
    ca_out
    put
.gadget ppc_subfic
    ri
    subs w10, w11, w10
    ca_out
    put
.gadget ppc_subfe
    rr
    ca_in
    sbcs w10, w11, w10
    ca_out
    put
.gadget ppc_subfme
    r1
    ca_in
    mov w11, #-1
    sbcs w10, w11, w10
    ca_out
    put1
.gadget ppc_subfze
    r1
    ca_in
    sbcs w10, wzr, w10
    ca_out
    put1

.gadget ppc_mullw
    rr
    mul w10, w10, w11
    put
.gadget ppc_mulli
    ri
    mul w10, w10, w11
    put
.gadget ppc_mulhw
    rr
    smull x10, w10, w11
    lsr x10, x10, #32
    put
.gadget ppc_mulhwu
    rr
    umull x10, w10, w11
    lsr x10, x10, #32
    put
/*
 * QEMU's results where the architecture leaves them undefined: rD = rA for a
 * divisor of 0, and for 0x80000000 / -1, which AArch64's sdiv already gives.
 */
.gadget ppc_divw
    rr
    sdiv w12, w10, w11
    cmp w11, #0
    csel w10, w10, w12, eq
    put
.gadget ppc_divwu
    rr
    udiv w12, w10, w11
    cmp w11, #0
    csel w10, w10, w12, eq
    put

.gadget ppc_and
    rr
    and w10, w10, w11
    put
.gadget ppc_andi
    ri
    and w10, w10, w11
    put
.gadget ppc_andc
    rr
    bic w10, w10, w11
    put
.gadget ppc_or
    rr
    orr w10, w10, w11
    put
.gadget ppc_ori
    ri
    orr w10, w10, w11
    put
.gadget ppc_orc
    rr
    orn w10, w10, w11
    put
.gadget ppc_xor
    rr
    eor w10, w10, w11
    put
.gadget ppc_xori
    ri
    eor w10, w10, w11
    put
.gadget ppc_nand
    rr
    and w10, w10, w11
    mvn w10, w10
    put
.gadget ppc_nor
    rr
    orr w10, w10, w11
    mvn w10, w10
    put
.gadget ppc_eqv
    rr
    eon w10, w10, w11
    put
.gadget ppc_extsb
    r1
    sxtb w10, w10
    put1
.gadget ppc_extsh
    r1
    sxth w10, w10
    put1
.gadget ppc_cntlzw
    r1
    clz w10, w10
    put1

/* slw, srw: a shift of 32 or more (rB bit 5) gives 0 */
.gadget ppc_slw
    rr
    lsl w12, w10, w11
    tst w11, #0x20
    csel w10, wzr, w12, ne
    put
.gadget ppc_srw
    rr
    lsr w12, w10, w11
    tst w11, #0x20
    csel w10, wzr, w12, ne
    put
/*
 * sraw: rA = rS >> n (arithmetic), n = rB & 31 or, with rB bit 5, all of rS's
 * bits; CA = rS negative and a 1 shifted out. QEMU's helper writes CA32 the
 * same; srawi does not touch it.
 */
.gadget ppc_sraw
    rr
    mov w13, #31
    tst w11, #0x20
    and w12, w11, #31
    csel w12, w13, w12, ne      /* n */
    mov w14, #1
    lsl w14, w14, w12
    sub w14, w14, #1            /* the bits shifted out... */
    csinv w14, w14, wzr, eq     /* ...all of them with bit 5 */
    tst w10, w14
    asr w11, w10, w12
    cset w12, ne
    cmp w10, #0
    csel w12, w12, wzr, lt
    str w12, [_cpu, #AOK_PPC_ENV_CA]
    str w12, [_cpu, #AOK_PPC_ENV_CA32]
    mov w10, w11
    put
/* srawi: [rA][rS][sh] */
.gadget ppc_srawi
    ri
    mov w14, #1
    lsl w14, w14, w11
    sub w14, w14, #1
    tst w10, w14
    cset w12, ne
    asr w13, w10, w11
    cmp w10, #0
    csel w12, w12, wzr, lt
    str w12, [_cpu, #AOK_PPC_ENV_CA]
    mov w10, w13
    put

/*
 * The rotates. [rA][rS][rotation | mask << 32] for rlwinm and rlwimi, the
 * rotation a right one (32 - SH, mod 32); [rA][rS][rB][mask] for rlwnm.
 */
.gadget ppc_rlwinm
    ri
    ror w10, w10, w11
    lsr x12, x11, #32
    and w10, w10, w12
    put
.gadget ppc_rlwimi
    ri
    ldr w13, [_cpu, x9]
    ror w10, w10, w11
    lsr x12, x11, #32
    and w10, w10, w12
    bic w13, w13, w12
    orr w10, w10, w13
    put
.gadget ppc_rlwnm
    rr
    ldr x12, [_ip, #24]
    neg w11, w11
    ror w10, w10, w11
    and w10, w10, w12
    str w10, [_cpu, x9]
    gret 4

/* ---- The condition register ------------------------------------------------
 *
 * A CR field is a word of its own (crf[]), LT GT EQ SO in its bits 3..0.
 */

/* CR0 from the signed value of \reg and XER[SO]: a record form's */
.macro cr0_of reg
    ldr w13, [_cpu, #AOK_PPC_ENV_SO]
    cmp \reg, #0
    mov w14, #AOK_PPC_CR_GT
    mov w15, #AOK_PPC_CR_LT
    csel w14, w15, w14, lt
    mov w15, #AOK_PPC_CR_EQ
    csel w14, w15, w14, eq
    orr w14, w14, w13
    str w14, [_cpu, #AOK_PPC_ENV_CRF]
.endm

/* [reg]: the record form's CR0, from the register the insn wrote */
.gadget ppc_cr0
    ldr x9, [_ip]
    ldr w10, [_cpu, x9]
    cr0_of w10
    gret 1

/* compares: [crf offset][rA][rB] or [crf offset][rA][imm] */
.macro cmp_tail lt, gt
    mov w12, #AOK_PPC_CR_EQ
    mov w13, #AOK_PPC_CR_GT
    csel w12, w13, w12, \gt
    mov w13, #AOK_PPC_CR_LT
    csel w12, w13, w12, \lt
    ldr w13, [_cpu, #AOK_PPC_ENV_SO]
    orr w12, w12, w13
    str w12, [_cpu, x9]
    gret 3
.endm
.gadget ppc_cmp
    rr
    cmp w10, w11
    cmp_tail lt, gt
.gadget ppc_cmpi
    ri
    cmp w10, w11
    cmp_tail lt, gt
.gadget ppc_cmpl
    rr
    cmp w10, w11
    cmp_tail lo, hi
.gadget ppc_cmpli
    ri
    cmp w10, w11
    cmp_tail lo, hi

/*
 * The CR logical ops: [crbD's field][crbA's field][crbB's field]
 * [sD | sA << 8 | sB << 16], each s the bit's position in its field
 * (3 for LT ... 0 for SO). A and B are read before D is written.
 */
.macro crop name
.gadget ppc_\name
    ldp x9, x10, [_ip]
    ldp x11, x12, [_ip, #16]
    ldr w10, [_cpu, x10]
    ldr w11, [_cpu, x11]
    lsr w13, w12, #8
    lsr w10, w10, w13
    lsr w13, w12, #16
    lsr w11, w11, w13
.endm
.macro crput
    ldr w13, [_cpu, x9]
    and w12, w12, #0xff
    mov w14, #1
    lsl w14, w14, w12
    lsl w10, w10, w12
    and w10, w10, w14
    bic w13, w13, w14
    orr w13, w13, w10
    str w13, [_cpu, x9]
    gret 4
.endm
    crop crand
    and w10, w10, w11
    crput
    crop cror
    orr w10, w10, w11
    crput
    crop crxor
    eor w10, w10, w11
    crput
    crop crnand
    and w10, w10, w11
    mvn w10, w10
    crput
    crop crnor
    orr w10, w10, w11
    mvn w10, w10
    crput
    crop creqv
    eon w10, w10, w11
    crput
    crop crandc
    bic w10, w10, w11
    crput
    crop crorc
    orn w10, w10, w11
    crput

/* mfcr: [rD] -- the eight fields, CR0 in the top nibble */
.gadget ppc_mfcr
    ldr x9, [_ip]
    add x15, _cpu, #AOK_PPC_ENV_CRF
    ldp w10, w11, [x15]
    ldp w12, w13, [x15, #8]
    lsl w10, w10, #28
    orr w10, w10, w11, lsl #24
    orr w10, w10, w12, lsl #20
    orr w10, w10, w13, lsl #16
    ldp w12, w13, [x15, #16]
    orr w10, w10, w12, lsl #12
    orr w10, w10, w13, lsl #8
    ldp w12, w13, [x15, #24]
    orr w10, w10, w12, lsl #4
    orr w10, w10, w13
    str w10, [_cpu, x9]
    gret 1

/* mtcrf: [rS][CRM] -- field 7 - n from rS bits 4n+3..4n where CRM bit n is set */
.gadget ppc_mtcrf
    ldp x9, x11, [_ip]
    ldr w10, [_cpu, x9]
    add x15, _cpu, #AOK_PPC_ENV_CRF
    .irp n, 0, 1, 2, 3, 4, 5, 6, 7
    tbz w11, #\n, 1f
    ubfx w12, w10, #(4 * \n), #4
    str w12, [x15, #(4 * (7 - \n))]
1:
    .endr
    gret 2

/* ---- XER ------------------------------------------------------------------ */

/* mfxer: [rD] -- xer with SO, OV and CA put back at bits 31, 30 and 29 */
.gadget ppc_mfxer
    ldr x9, [_ip]
    ldr w10, [_cpu, #AOK_PPC_ENV_XER]
    ldr w11, [_cpu, #AOK_PPC_ENV_SO]
    ldr w12, [_cpu, #AOK_PPC_ENV_OV]
    ldr w13, [_cpu, #AOK_PPC_ENV_CA]
    orr w10, w10, w11, lsl #31
    orr w10, w10, w12, lsl #30
    orr w10, w10, w13, lsl #29
    str w10, [_cpu, x9]
    gret 1

/* mtxer: [rS] -- the split flags out of bits 31, 30, 29, 19 and 18 */
.gadget ppc_mtxer
    ldr x9, [_ip]
    ldr w10, [_cpu, x9]
    mov w11, #0x1ff3ffff
    and w11, w10, w11
    str w11, [_cpu, #AOK_PPC_ENV_XER]
    ubfx w11, w10, #31, #1
    str w11, [_cpu, #AOK_PPC_ENV_SO]
    ubfx w11, w10, #30, #1
    str w11, [_cpu, #AOK_PPC_ENV_OV]
    ubfx w11, w10, #29, #1
    str w11, [_cpu, #AOK_PPC_ENV_CA]
    ubfx w11, w10, #19, #1
    str w11, [_cpu, #AOK_PPC_ENV_OV32]
    ubfx w11, w10, #18, #1
    str w11, [_cpu, #AOK_PPC_ENV_CA32]
    gret 1

/* mcrxr: [crf offset] -- SO OV CA into the field's top three bits, then cleared */
.gadget ppc_mcrxr
    ldr x9, [_ip]
    ldr w10, [_cpu, #AOK_PPC_ENV_SO]
    ldr w11, [_cpu, #AOK_PPC_ENV_OV]
    ldr w12, [_cpu, #AOK_PPC_ENV_CA]
    lsl w10, w10, #3
    orr w10, w10, w11, lsl #2
    orr w10, w10, w12, lsl #1
    str w10, [_cpu, x9]
    str wzr, [_cpu, #AOK_PPC_ENV_SO]
    str wzr, [_cpu, #AOK_PPC_ENV_OV]
    str wzr, [_cpu, #AOK_PPC_ENV_CA]
    gret 1

/* sync (in user mode) and eieio: a full barrier, as TCG's TCG_MO_ALL | TCG_BAR_SC */
.gadget ppc_sync
    dmb ish
    gret

/* ---- Guest memory ----------------------------------------------------------
 *
 * Stream of a load or store: [gadget][rD/rS offset][rA offset][d][word] for
 * the D form, whose address is (rA|0) + d, and [gadget][rD/rS offset]
 * [rA offset][rB offset][word] for the X form, (rA|0) + rB. Where rA is 0
 * its offset is aok_zero's. The last word is the insn, and above it its
 * distance from the TB's first insn: what the slow path needs to name the
 * insn should it fault.
 *
 * The softmmu fast path, as TCG's own backends inline it: index this TB's
 * fast table by the page number (folded, CPU_TLB_INDEX_FOLD), compare the
 * entry's tag with the address, and on a match the entry's addend turns the
 * guest address into a host one. The tag is compared with the address's page
 * AND its low alignment bits, so only an aligned access to a page with no
 * flags set hits; a misaligned one, MMIO, a watched or not-yet-dirty page
 * and a real miss all take the slow path, which is cputlb's.
 *
 * The guest is big-endian: a load reverses what it read, a store what it
 * writes. The slow path does the whole access in C, a big-endian one, and
 * may raise a guest exception and not return; when it does return, a load
 * rejoins the body with the value as the guest sees it, past the reversal.
 *
 * An update form (lwzu ...) writes the address to rA once the access is
 * done, so that a fault leaves rA as it was; the address waits in w8, which
 * the slow path keeps across its call to C.
 */
_addr   .req x7
#define TLB_FOLD        8       /* CPU_TLB_INDEX_FOLD */
#define TLB_SHIFT       7       /* TARGET_PAGE_BITS - CPU_TLB_ENTRY_BITS */
#define TLBE_READ       0
#define TLBE_WRITE      8
#define TLBE_ADDEND     24

/* _addr = (rA|0) + d, or (rA|0) + rB: 32 bits, wrapping */
.macro ea_d
    ldp x9, x10, [_ip, #8]
    ldr w9, [_cpu, x9]
    add w7, w9, w10
.endm
.macro ea_x
    ldp x9, x10, [_ip, #8]
    ldr w9, [_cpu, x9]
    ldr w10, [_cpu, x10]
    add w7, w9, w10
.endm

/* _addr from the guest address to the host one, or to \miss */
.macro tlb_probe size, tag, miss
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
    b.ne \miss
    add _addr, _addr, x10
.endm

/* x0 = env, x1 = the guest address, x(\pcreg) = the insn's pc, x(\pcreg+1) = the insn */
.macro slow_args pcreg, insnreg
    ldr x\pcreg, [_ip, #24]
    mov x0, _cpu
    mov x1, _addr
    and x\insnreg, x\pcreg, #0xffffffff
    lsr x\pcreg, x\pcreg, #32
    add w\pcreg, w19, w\pcreg
.endm

/*
 * A load: \ld reads \size bits, \swap puts them in the guest's order, \ext
 * extends the value (to the register's 32 bits).
 */
.macro load name, size, ld, swap, ext, form, upd=0, le=
.gadget ppc_\name
    ea_\form
    .if \upd
    mov w8, w7
    .endif
    tlb_probe \size, TLBE_READ, 8f
    \ld w10, [_addr]
    .ifnb \swap
    \swap w10, w10
    .endif
1:
    .ifnb \ext
    \ext w10, w10
    .endif
    ldr x9, [_ip]
    .if \upd
    ldr x11, [_ip, #8]
    str w10, [_cpu, x9]
    str w8, [_cpu, x11]
    .else
    str w10, [_cpu, x9]
    .endif
    gret 4
8:  aok_fp_end
    slow_args 2, 3
    str x8, [sp, #-16]!
    bl SYM(aok_ppc_helper_load\size\le)
    ldr x8, [sp], #16
    mov w10, w0
    b 1b
.endm

/* A store: \st writes \size bits of what \swap has put in memory's order. */
.macro store name, size, st, swap, form, upd=0, le=
.gadget ppc_\name
    ea_\form
    ldr x9, [_ip]
    ldr w6, [_cpu, x9]
    .if \upd
    mov w8, w7
    .endif
    tlb_probe \size, TLBE_WRITE, 8f
    .ifnb \swap
    \swap w10, w6
    \st w10, [_addr]
    .else
    \st w6, [_addr]
    .endif
1:
    .if \upd
    ldr x9, [_ip, #8]
    str w8, [_cpu, x9]
    .endif
    gret 4
8:  aok_fp_end
    slow_args 3, 4
    mov w2, w6
    str x8, [sp, #-16]!
    bl SYM(aok_ppc_helper_store\size\le)
    ldr x8, [sp], #16
    b 1b
.endm

/* (sxth/sxtb take x and w registers alike; an empty \ext is none) */
.irp form, d, x
    load lbz_\form, 8, ldrb, , , \form
    load lhz_\form, 16, ldrh, rev16, , \form
    load lha_\form, 16, ldrh, rev16, sxth, \form
    load lwz_\form, 32, ldr, rev, , \form
    load lbzu_\form, 8, ldrb, , , \form, 1
    load lhzu_\form, 16, ldrh, rev16, , \form, 1
    load lhau_\form, 16, ldrh, rev16, sxth, \form, 1
    load lwzu_\form, 32, ldr, rev, , \form, 1
    store stb_\form, 8, strb, , \form
    store sth_\form, 16, strh, rev16, \form
    store stw_\form, 32, str, rev, \form
    store stbu_\form, 8, strb, , \form, 1
    store sthu_\form, 16, strh, rev16, \form, 1
    store stwu_\form, 32, str, rev, \form, 1
.endr
/*
 * The byte-reversed ones, X form only: memory's order is the host's, and
 * their slow paths make little-endian accesses (the _le helpers).
 */
    load lhbrx, 16, ldrh, , , x, 0, _le
    load lwbrx, 32, ldr, , , x, 0, _le
    store sthbrx, 16, strh, , x, 0, _le
    store stwbrx, 32, str, , x, 0, _le

/* ---- Floating point --------------------------------------------------------
 *
 * The FPRs are doublewords of vsr[] (fpr_offset()); an operand is the
 * offset of one. FPSCR is at AOK_PPC_ENV_FPSCR.
 */
#define FPSCR_HI (AOK_PPC_ENV_FPSCR & ~0xfff)
#define FPSCR_LO (AOK_PPC_ENV_FPSCR & 0xfff)
.macro fpscr_at reg
    add \reg, _cpu, #(FPSCR_HI >> 12), lsl #12
.endm

/* w10, a single's bits, to x10, the double's: DOUBLE(), helper_todouble */
.macro todouble
    ubfx w12, w10, #23, #8
    and w13, w10, #0x7fffff
    lsr w11, w10, #31
    lsl x11, x11, #63
    cbz w12, 2f
    cmp w12, #0xff
    mov w14, #0x7ff
    add w15, w12, #896
    csel w12, w14, w15, eq
    orr x10, x11, x12, lsl #52
    orr x10, x10, x13, lsl #29
    b 3f
2:  mov x10, x11                /* zero, or a denormal to normalize */
    cbz w13, 3f
    clz w14, w13
    sub w14, w14, #8            /* shift */
    mov w15, #896
    sub w15, w15, w14
    orr x10, x10, x15, lsl #52
    add w14, w14, #29
    lsl x13, x13, x14
    add x10, x10, x13
3:
.endm

/* x10, a double's bits, to w10, the single's: SINGLE(), helper_tosingle */
.macro tosingle
    ubfx x12, x10, #52, #11
    cmp x12, #896
    b.ls 2f
    lsr x13, x10, #62
    ubfx x14, x10, #29, #30
    orr w10, w14, w13, lsl #30
    b 3f
2:  lsr x13, x10, #63
    lsl w13, w13, #31
    cmp x12, #874
    b.lo 4f
    ubfx x14, x10, #0, #52
    orr x14, x14, #(1 << 52)
    mov x15, #926
    sub x15, x15, x12
    lsr x14, x14, x15
    orr w13, w13, w14
4:  mov w10, w13
3:
.endm

/*
 * The FP loads and stores: the integer ones' streams, on an FPR. lfs reads a
 * single and makes it a double, stfs the reverse, both without rounding;
 * stfiwx stores the FPR's low word. Their slow paths are the fload/fstore
 * helpers, which store access_type as FP accesses do.
 */
.macro fload name, size, form, upd=0
.gadget ppc_\name
    ea_\form
    .if \upd
    mov w8, w7
    .endif
    tlb_probe \size, TLBE_READ, 8f
    .if \size == 64
    ldr x10, [_addr]
    rev x10, x10
    .else
    ldr w10, [_addr]
    rev w10, w10
    .endif
1:
    .if \size == 32
    todouble
    .endif
    ldr x9, [_ip]
    str x10, [_cpu, x9]
    .if \upd
    ldr x11, [_ip, #8]
    str w8, [_cpu, x11]
    .endif
    gret 4
8:  aok_fp_end
    slow_args 2, 3
    str x8, [sp, #-16]!
    bl SYM(aok_ppc_helper_fload\size)
    ldr x8, [sp], #16
    mov x10, x0
    b 1b
.endm

.macro fstore name, size, form, upd=0, iw=0
.gadget ppc_\name
    ldr x9, [_ip]
    ldr x6, [_cpu, x9]
    .if \size == 32 && \iw == 0
    mov x10, x6
    tosingle
    mov w6, w10
    .endif
    ea_\form
    .if \upd
    mov w8, w7
    .endif
    tlb_probe \size, TLBE_WRITE, 8f
    .if \size == 64
    rev x10, x6
    str x10, [_addr]
    .else
    rev w10, w6
    str w10, [_addr]
    .endif
1:
    .if \upd
    ldr x9, [_ip, #8]
    str w8, [_cpu, x9]
    .endif
    gret 4
8:  aok_fp_end
    slow_args 3, 4
    mov x2, x6
    str x8, [sp, #-16]!
    bl SYM(aok_ppc_helper_fstore\size)
    ldr x8, [sp], #16
    b 1b
.endm

.irp form, d, x
    fload lfs_\form, 32, \form
    fload lfsu_\form, 32, \form, 1
    fload lfd_\form, 64, \form
    fload lfdu_\form, 64, \form, 1
    fstore stfs_\form, 32, \form
    fstore stfsu_\form, 32, \form, 1
    fstore stfd_\form, 64, \form
    fstore stfdu_\form, 64, \form, 1
.endr
    fstore stfiwx, 32, x, 0, 1

/* fmr, fneg, fabs, fnabs: [frD][frB], FPSCR untouched */
.macro fmove name, op
.gadget ppc_\name
    ldp x9, x10, [_ip]
    ldr x10, [_cpu, x10]
    .ifnb \op
    \op x10, x10, #0x8000000000000000
    .endif
    str x10, [_cpu, x9]
    gret 2
.endm
    fmove fmr
    fmove fneg, eor
    fmove fnabs, orr
.gadget ppc_fabs
    ldp x9, x10, [_ip]
    ldr x10, [_cpu, x10]
    and x10, x10, #0x7fffffffffffffff
    str x10, [_cpu, x9]
    gret 2

/* A record form's CR1: FPSCR's top four bits (FX FEX VX OX) */
.gadget ppc_cr1
    fpscr_at x15
    ldr w10, [x15, #FPSCR_LO]
    lsr w10, w10, #28
    str w10, [_cpu, #(AOK_PPC_ENV_CRF + 4)]
    gret

/* mffs: [frD] -- FPSCR, zero-extended (QEMU's resets softfloat's flags too: see fp_check) */
.gadget ppc_mffs
    ldr x9, [_ip]
    fpscr_at x15
    ldr w10, [x15, #FPSCR_LO]
    str x10, [_cpu, x9]
    gret 1

/* fsel: [frD][frA][frC][frB] -- frC if frA >= 0 (-0 too) and not a NaN, else frB */
.gadget ppc_fsel
    ldp x9, x10, [_ip]
    ldp x11, x12, [_ip, #16]
    ldr d0, [_cpu, x10]
    fcmp d0, #0.0
    csel x13, x11, x12, ge
    ldr x13, [_cpu, x13]
    str x13, [_cpu, x9]
    gret 4

/*
 * Arithmetic on the host's FP unit, where it gives what QEMU's helpers do.
 *
 * TCG's code for an FP op resets softfloat's flags, calls the op's helper,
 * writes the FPR, sets FPRF from the result and checks the flags
 * (do_float_check_status): an invalid op, a zero divide, an overflow or an
 * underflow sets bits of FPSCR and may trap; an inexact result sets XX and
 * FX, and FI is set to whether it was. A clean result does no more than
 * that, and with RN to nearest, NI off and the XE, UE and OE enables clear it
 * cannot trap.
 *
 * The host's FPSR could say which results are clean, but writing it stalls
 * the FP unit (some ten times an fmadd on an M5) and reading it waits for it.
 * So the gadgets do without: each finds whether its result was exact by an
 * error-free transformation (TwoSum for an add, an FMA for the error of a
 * product, the remainder of a quotient or a square root, and for the fused
 * ops the exact product against the exact difference of the result and the
 * addend, each a pair of doubles), in the exponent range where that is
 * exact; and the rest is in the values: a NaN (invalid, or one propagated,
 * which PowerPC does its own way), an infinity (an overflow or a zero
 * divide), a zero that was inexact or a result so small that tininess
 * before rounding (QEMU's for PowerPC) and after it (the host's) could
 * disagree, or operands outside that range, and the insn is done again in C
 * by QEMU's helpers in TCG's order (aok_ppc_helper_fp). FPCR stays what
 * QEMU's own code runs under (zero: RN, no flush to zero, no default NaN).
 * d8-d15 are the C caller's and are not touched.
 */
.macro fp_check slow
    fpscr_at x15
    ldr w12, [x15, #FPSCR_LO]
    mov w13, #AOK_PPC_FPSCR_SLOW
    tst w12, w13
    b.ne \slow
.endm

/* to \slow unless \reg's exponent field is in [\lo, \hi] (so: finite, and not tiny) */
.macro exp_in reg, lo, hi, slow
    fmov x13, \reg
    ubfx x13, x13, #52, #11
    sub x13, x13, #\lo
    cmp x13, #(\hi - \lo)
    b.hi \slow
.endm

/*
 * x10 = d0's bits and w16 its class for FPRF, or \slow: an infinity, a NaN,
 * a denormal, or an inexact zero (an underflow). w11 is whether it is inexact.
 */
.macro fp_class slow
    fmov x10, d0
    ubfx x14, x10, #52, #11
    mov w16, #0x04              /* + normal */
    cbz x14, 3f
    cmp x14, #0x7ff
    b.eq \slow
    b 4f
3:  lsl x17, x10, #1
    cbnz x17, \slow
    cbnz w11, \slow
    mov w16, #0x02              /* + zero */
4:  tbz x10, #63, 5f
    add w17, w16, #4            /* - normal 8 ... */
    cmp w16, #0x02
    mov w16, #0x12              /* ... - zero 0x12 */
    csel w16, w16, w17, eq
5:
.endm

/* The FPR at the first operand, FPRF from w16, FI and (if inexact) XX and FX from w11 */
.macro fp_store
    ldr x9, [_ip]
    str x10, [_cpu, x9]
    bic w12, w12, #(AOK_PPC_FPSCR_FPRF | AOK_PPC_FPSCR_FI)
    orr w12, w12, w16, lsl #12
    cbz w11, 6f
    movz w17, #((AOK_PPC_FPSCR_FX | AOK_PPC_FPSCR_XX | AOK_PPC_FPSCR_FI) >> 16), lsl #16
    orr w12, w12, w17
6:  str w12, [x15, #FPSCR_LO]
.endm

/* The slow path: [... word] at \off, the insn and its distance from the TB's first */
.macro fp_slow off
    ldr x9, [_ip, #\off]
    mov x0, _cpu
    lsr x1, x9, #32
    add w1, w19, w1
    and x2, x9, #0xffffffff
    bl SYM(aok_ppc_helper_fp)
.endm

/*
 * fadd, fsub: [frD][frA][frB][word]. A sum is exact when it is tiny, so only
 * a denormal one is the slow path's; TwoSum is exact wherever the sum is
 * finite.
 */
.macro fp_addsub name, sub
.gadget ppc_\name
    fp_check 8f
    ldp x9, x10, [_ip, #8]
    ldr d1, [_cpu, x9]
    ldr d2, [_cpu, x10]
    .if \sub
    fneg d2, d2
    .endif
    fadd d0, d1, d2
    fsub d4, d0, d1             /* TwoSum's error */
    fsub d5, d0, d4
    fsub d6, d1, d5
    fsub d7, d2, d4
    fadd d6, d6, d7
    fcmp d6, #0.0
    cset w11, ne
    fp_class 8f
    fp_store
    gret 4
8:  fp_slow 24
    gret 4
.endm
    fp_addsub fadd, 0
    fp_addsub fsub, 1

/* fmul: [frD][frA][frC][word]; the error of a product is a*c - r, exact for r >= 2^-969 */
.gadget ppc_fmul
    fp_check 8f
    ldp x9, x10, [_ip, #8]
    ldr d1, [_cpu, x9]
    ldr d2, [_cpu, x10]
    fmul d0, d1, d2
    exp_in d0, 54, 2046, 8f
    fnmsub d4, d1, d2, d0
    fcmp d4, #0.0
    cset w11, ne
    fp_class 8f
    fp_store
    gret 4
8:  fp_slow 24
    gret 4

/* fdiv: [frD][frA][frB][word]; a quotient is exact if its remainder a - q*b is 0 */
.gadget ppc_fdiv
    fp_check 8f
    ldp x9, x10, [_ip, #8]
    ldr d1, [_cpu, x9]
    ldr d2, [_cpu, x10]
    fdiv d0, d1, d2
    exp_in d0, 54, 2046, 8f
    exp_in d1, 110, 2046, 8f
    exp_in d2, 54, 2046, 8f
    fmsub d4, d0, d2, d1
    fcmp d4, #0.0
    cset w11, ne
    fp_class 8f
    fp_store
    gret 4
8:  fp_slow 24
    gret 4

/* fsqrt: [frD][frB][word]; a square root is exact if x - s*s is 0 */
.gadget ppc_fsqrt
    fp_check 8f
    ldr x9, [_ip, #8]
    ldr d1, [_cpu, x9]
    fsqrt d0, d1
    exp_in d1, 110, 2046, 8f
    exp_in d0, 54, 2046, 8f
    fmsub d4, d0, d0, d1
    fcmp d4, #0.0
    cset w11, ne
    fp_class 8f
    fp_store
    gret 3
8:  fp_slow 16
    gret 3

/*
 * [frD][frA][frC][frB][word]: A*C + B, and the rest, fused as PowerPC's are:
 * r = fma(A, C, B'), B' being B or -B. It is exact if A*C = r - B' exactly,
 * and both are pairs of doubles normalized the same way (rounding to nearest
 * is a function of the exact value): A*C = ph + pl (ph = A*C rounded,
 * pl = fma(A, C, -ph)), r - B' = d + ed (TwoSum). fnmadd and fnmsub negate
 * the rounded result, as QEMU's float_muladd_negate_result does: so the sign
 * of a zero is theirs.
 */
.macro fp_fma name, sub, neg
.gadget ppc_\name
    fp_check 8f
    ldp x9, x10, [_ip, #8]
    ldr x11, [_ip, #24]
    ldr d1, [_cpu, x9]
    ldr d2, [_cpu, x10]
    ldr d3, [_cpu, x11]
    .if \sub
    fneg d3, d3
    .endif
    fmadd d0, d1, d2, d3
    exp_in d0, 54, 2046, 8f
    fmul d4, d1, d2             /* ph */
    exp_in d4, 54, 2045, 8f
    fnmsub d5, d1, d2, d4       /* pl */
    fsub d6, d0, d3             /* d = r - B' */
    fsub d7, d6, d0
    fsub d16, d6, d7
    fsub d17, d0, d16
    fadd d18, d3, d7
    fsub d17, d17, d18          /* ed */
    fcmp d4, d6
    fccmp d5, d17, #0, eq
    cset w11, ne
    .if \neg
    fneg d0, d0
    .endif
    fp_class 8f
    fp_store
    gret 5
8:  fp_slow 32
    gret 5
.endm
    fp_fma fmadd, 0, 0
    fp_fma fmsub, 1, 0
    fp_fma fnmadd, 0, 1
    fp_fma fnmsub, 1, 1

/*
 * frsp: [frD][frB][word] -- to a single and back, which is exact; inexact if
 * that is not the operand. A single result in the denormal range, or an
 * inexact zero, is the slow path's.
 */
.gadget ppc_frsp
    fp_check 8f
    ldr x9, [_ip, #8]
    ldr d1, [_cpu, x9]
    fcmp d1, d1
    b.vs 8f
    fcvt s0, d1
    fmov w11, s0
    and w11, w11, #0x7fffffff
    sub w11, w11, #1
    mov w16, #0x00ffffff
    cmp w11, w16
    b.lo 8f
    fcvt d0, s0
    fcmp d0, d1
    cset w11, ne
    fp_class 8f
    fp_store
    gret 3
8:  fp_slow 16
    gret 3

/*
 * fctiw, fctiwz: [frD][frB][word] -- to a word, which QEMU's helper returns
 * sign-extended to the FPR's 64 bits; inexact if the word converted back is
 * not the operand. FPRF is not touched. A NaN, and a result at either end of
 * the range (where the host saturates what PowerPC calls invalid), are the
 * slow path's.
 */
.macro fcti name, op
.gadget ppc_\name
    fp_check 8f
    ldr x9, [_ip, #8]
    ldr d1, [_cpu, x9]
    fcmp d1, d1
    b.vs 8f
    \op w10, d1
    mov w13, #0x7fffffff
    cmp w10, w13
    b.eq 8f
    mov w13, #0x80000000
    cmp w10, w13
    b.eq 8f
    scvtf d4, w10
    fcmp d4, d1
    cset w11, ne
    sxtw x10, w10
    ldr x9, [_ip]
    str x10, [_cpu, x9]
    bic w12, w12, #AOK_PPC_FPSCR_FI
    cbz w11, 6f
    movz w17, #((AOK_PPC_FPSCR_FX | AOK_PPC_FPSCR_XX | AOK_PPC_FPSCR_FI) >> 16), lsl #16
    orr w12, w12, w17
6:  str w12, [x15, #FPSCR_LO]
    gret 3
8:  fp_slow 16
    gret 3
.endm
    fcti fctiw, fcvtns
    fcti fctiwz, fcvtzs

/*
 * fcmpu, fcmpo: [crf offset][frA][frB][word]. Two numbers compare as QEMU's
 * helpers have it: the CR field and FPSCR's FPCC get LT, GT or EQ, and FI is
 * cleared (no flag is raised). A NaN is the slow path's: unordered, VXSNAN
 * and VXVC.
 */
.gadget ppc_fcmp
    ldp x9, x10, [_ip]
    ldr x11, [_ip, #16]
    ldr d0, [_cpu, x10]
    ldr d1, [_cpu, x11]
    fcmp d0, d1
    b.vs 8f
    mov w12, #2
    mov w13, #4
    csel w12, w13, w12, gt
    mov w13, #8
    csel w12, w13, w12, mi
    str w12, [_cpu, x9]
    fpscr_at x15
    ldr w13, [x15, #FPSCR_LO]
    bic w13, w13, #AOK_PPC_FPSCR_FPCC
    bic w13, w13, #AOK_PPC_FPSCR_FI
    orr w13, w13, w12, lsl #12
    str w13, [x15, #FPSCR_LO]
    gret 4
8:  fp_slow 24
    gret 4

/* ---- Leaving a TB ----------------------------------------------------------
 *
 * A way out is aok_gadget_goto32's two operands, [pc delta][slot], and a
 * guest code address in the stream is its distance from the TB's entry pc.
 * Each way out is its own copy of aok_goto32_tail rather than a jump to it,
 * so that each ends in an indirect branch of its own, which the host's
 * predictor can learn apart from the rest.
 */
#define WAY_WORDS 2
.macro leave off
    ldp x9, x10, [_ip, #\off]
    ldr w11, [_exitreq]
    add w19, w19, w9
    ldr _ip, [x10]
    str w19, [_pcp]
    tbnz w11, #31, 7f
    gret AOK_ENTER_WORDS
7:  b SYM(aok_exit_requested)
.endm

/* b: [delta][slot] */
.gadget ppc_b
    leave 0

/* bl: [link delta][delta][slot] -- LR = the next insn's address */
.gadget ppc_bl
    ldr x9, [_ip]
    add w9, w19, w9
    str w9, [_cpu, #AOK_PPC_ENV_LR]
    leave 8

/*
 * The link of a conditional branch with LK (bcl), which a CPU writes whether
 * the branch is taken or not: [link delta], before the branch's own gadget.
 */
.gadget ppc_set_lr
    ldr x9, [_ip]
    add w9, w19, w9
    str w9, [_cpu, #AOK_PPC_ENV_LR]
    gret 1

/*
 * bc on a CR bit: [crf offset][bit][taken way][fall-through way], the bit
 * set (bc_t) or clear (bc_f). (A way is WAY_WORDS words.)
 */
.gadget ppc_bc_t
    ldp x9, x10, [_ip]
    ldr w9, [_cpu, x9]
    tst w9, w10
    b.eq 1f
    leave 16
1:  leave 32

.gadget ppc_bc_f
    ldp x9, x10, [_ip]
    ldr w9, [_cpu, x9]
    tst w9, w10
    b.ne 1f
    leave 16
1:  leave 32

/* bdnz, bdz: [taken way][fall-through way]; CTR is decremented first */
.gadget ppc_bdnz
    ldr w9, [_cpu, #AOK_PPC_ENV_CTR]
    sub w9, w9, #1
    str w9, [_cpu, #AOK_PPC_ENV_CTR]
    cbz w9, 1f
    leave 0
1:  leave 16

.gadget ppc_bdz
    ldr w9, [_cpu, #AOK_PPC_ENV_CTR]
    sub w9, w9, #1
    str w9, [_cpu, #AOK_PPC_ENV_CTR]
    cbnz w9, 1f
    leave 0
1:  leave 16

/*
 * bc on CTR and a CR bit at once (bdnzt, bdnzf, bdzt, bdzf): [crf offset][bit]
 * [taken way][fall-through way]. CTR is decremented whatever the bit.
 */
.macro bdc name, ctrz, set
.gadget ppc_\name
    ldr w11, [_cpu, #AOK_PPC_ENV_CTR]
    sub w11, w11, #1
    str w11, [_cpu, #AOK_PPC_ENV_CTR]
    ldp x9, x10, [_ip]
    ldr w9, [_cpu, x9]
    .if \ctrz
    cbnz w11, 1f
    .else
    cbz w11, 1f
    .endif
    tst w9, w10
    .if \set
    b.eq 1f
    .else
    b.ne 1f
    .endif
    leave 16
1:  leave 32
.endm
    bdc bdnzt, 0, 1
    bdc bdnzf, 0, 0
    bdc bdzt, 1, 1
    bdc bdzf, 1, 0

/* ---- Indirect branches ---------------------------------------------------
 *
 * blr, bctr and their linking forms: [link delta] for those, then
 * [flags | cflags << 32][cs_base]. The target is read before the link is
 * written (blrl branches to the old LR), its low two bits cleared; then
 * aok_ppc_lookup_pc finds the TB there. A TB that may not look its
 * successor up has the _exit forms, after which the stream exits.
 */
.macro indirect name, src, link
.gadget ppc_\name
    ldr w10, [_cpu, #\src]
    and w10, w10, #0xfffffffc
    .if \link
    ldr x9, [_ip], #8
    add w9, w19, w9
    str w9, [_cpu, #AOK_PPC_ENV_LR]
    .endif
    str w10, [_pcp]
    b SYM(aok_ppc_lookup_pc)

.gadget ppc_\name\()_exit
    ldr w10, [_cpu, #\src]
    and w10, w10, #0xfffffffc
    .if \link
    ldr x9, [_ip], #8
    add w9, w19, w9
    str w9, [_cpu, #AOK_PPC_ENV_LR]
    .endif
    str w10, [_pcp]
    gret
.endm
    indirect blr, AOK_PPC_ENV_LR, 0
    indirect blrl, AOK_PPC_ENV_LR, 1
    indirect bctr, AOK_PPC_ENV_CTR, 0
    indirect bctrl, AOK_PPC_ENV_CTR, 1

/*
 * bclr on a CR bit, without LK (beqlr, bnelr ...): [crf offset][bit]
 * [fall-through way][flags | cflags << 32][cs_base].
 */
.macro bclrc name, set
.gadget ppc_\name
    ldp x9, x10, [_ip]
    ldr w9, [_cpu, x9]
    tst w9, w10
    .if \set
    b.eq 1f
    .else
    b.ne 1f
    .endif
    ldr w10, [_cpu, #AOK_PPC_ENV_LR]
    and w10, w10, #0xfffffffc
    str w10, [_pcp]
    add _ip, _ip, #32
    b SYM(aok_ppc_lookup_pc)
1:  leave 16
.endm
    bclrc bclr_t, 1
    bclrc bclr_f, 0

/*
 * [flags | cflags << 32][cs_base] -- aok_gadget_lookup with tb_lookup()'s
 * first step done here (aok_lookup_jc): the TB for env->nip is usually in
 * cpu->tb_jmp_cache. Anything else, and any breakpoint at all, is
 * aok_lookup_tb_ptr's.
 */
.gadget ppc_lookup
    ldr w10, [_pcp]
    /* (entered here with nip in x10, zero-extended, and _ip at the two operands) */
    .globl SYM(aok_ppc_lookup_pc)
SYM(aok_ppc_lookup_pc):
    aok_lookup_jc

/* ---- Calls to C ----------------------------------------------------------
 *
 * [function][pc delta][insn] -- an insn done in C: function(env, pc, insn).
 * It finds its operands in the insn and env, and may raise an exception.
 */
.gadget ppc_call
    aok_fp_end
    ldp x9, x1, [_ip]
    ldr x2, [_ip, #16]
    mov x0, _cpu
    add w1, w19, w1
    blr x9
    gret 3
