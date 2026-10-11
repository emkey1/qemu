/*
 * AOK gadgets for RISC-V guests (RV64): the integer base, M, Zba, Zbb, Zbs
 * and Zicond, loads and stores through the softmmu TLB, and branches.
 *
 * The arithmetic gadgets are iSH-AOK's (jit/guest-riscv64/alu.S). Operands
 * are byte offsets into CPURISCVState, so one gadget serves every register.
 * Reg-reg stream: [gadget][rd offset][rs1 offset][rs2 offset]
 * Reg-imm stream: [gadget][rd offset][rs1 offset][imm]
 * with the immediate already sign-extended to 64 bits. W forms compute in
 * 32 bits and sign-extend, the RV64 rule.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "accel/tcg/aok-asm.h"

    .text

/* ---- Integer arithmetic ------------------------------------------------- */

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

// Two variants per op: _rr (reg-reg) and _ri (reg-imm) where the ISA has
// both. Shift immediates arrive as the raw 0-63 shamt.
.macro alu_op name, insn:vararg
.gadget rv_\name\()_rr
    alu_rr_head
    \insn
    alu_tail
.gadget rv_\name\()_ri
    alu_head
    \insn
    alu_tail
.endm

alu_op add,  add x10, x10, x11
alu_op and,  and x10, x10, x11
alu_op or,   orr x10, x10, x11
alu_op xor,  eor x10, x10, x11
alu_op sll,  lsl x10, x10, x11
alu_op srl,  lsr x10, x10, x11
alu_op sra,  asr x10, x10, x11
// slt/sltu spelled out: `;` inside a macro argument is a statement
// separator to gas, so the two-instruction body can't ride the vararg.
.gadget rv_slt_rr
    alu_rr_head
    cmp x10, x11
    cset x10, lt
    alu_tail
.gadget rv_slt_ri
    alu_head
    cmp x10, x11
    cset x10, lt
    alu_tail
.gadget rv_sltu_rr
    alu_rr_head
    cmp x10, x11
    cset x10, lo
    alu_tail
.gadget rv_sltu_ri
    alu_head
    cmp x10, x11
    cset x10, lo
    alu_tail

// W-suffix 32-bit forms (sign-extended results)
.macro alu_opw name, insn:vararg
.gadget rv_\name\()w_rr
    alu_rr_head
    \insn
    sxtw x10, w10
    alu_tail
.gadget rv_\name\()w_ri
    alu_head
    \insn
    sxtw x10, w10
    alu_tail
.endm

alu_opw add, add w10, w10, w11
alu_opw sll, lsl w10, w10, w11
alu_opw srl, lsr w10, w10, w11
alu_opw sra, asr w10, w10, w11

// sub/subw have no immediate form
.gadget rv_sub_rr
    alu_rr_head
    sub x10, x10, x11
    alu_tail
.gadget rv_subw_rr
    alu_rr_head
    sub w10, w10, w11
    sxtw x10, w10
    alu_tail

// ---- M extension ----------------------------------------------------------
.gadget rv_mul_rr
    alu_rr_head
    mul x10, x10, x11
    alu_tail
.gadget rv_mulw_rr
    alu_rr_head
    mul w10, w10, w11
    sxtw x10, w10
    alu_tail
.gadget rv_mulh_rr
    alu_rr_head
    smulh x10, x10, x11
    alu_tail
.gadget rv_mulhu_rr
    alu_rr_head
    umulh x10, x10, x11
    alu_tail
.gadget rv_mulhsu_rr
    // signed(rs1) * unsigned(rs2), high half: smulh then correct — the
    // standard identity: mulhsu(a,b) = smulh(a,b) + (a<0 ? 0 : 0) ... the
    // clean form: umulh(a,b) - (a<0 ? b : 0).
    alu_rr_head
    umulh x12, x10, x11
    cmp x10, #0
    csel x13, x11, xzr, lt
    sub x10, x12, x13
    alu_tail

// RISC-V division semantics (RV spec table 7.1): x/0 = -1 (divu: all
// ones), rem by 0 = rs1, INT_MIN/-1 = INT_MIN rem 0. AArch64 sdiv already
// gives INT_MIN for the overflow case and 0 for /0, so only the /0 result
// needs fixing; rem is msub-derived which yields rs1 automatically when
// the (patched) quotient is forced to the spec value... it does NOT for
// div-by-zero (spec quotient -1 would give rem = rs1 + rs2), so rem
// branches on zero explicitly.
.gadget rv_div_rr
    alu_rr_head
    cbz x11, 1f
    sdiv x10, x10, x11
    alu_tail
1:  mov x10, #-1
    alu_tail
.gadget rv_divu_rr
    alu_rr_head
    cbz x11, 1f
    udiv x10, x10, x11
    alu_tail
1:  mov x10, #-1
    alu_tail
.gadget rv_rem_rr
    alu_rr_head
    cbz x11, 1f              // rem by zero = rs1 (x10 already holds it)
    sdiv x12, x10, x11
    msub x10, x12, x11, x10
1:  alu_tail
.gadget rv_remu_rr
    alu_rr_head
    cbz x11, 1f
    udiv x12, x10, x11
    msub x10, x12, x11, x10
1:  alu_tail
.gadget rv_divw_rr
    alu_rr_head
    cbz w11, 1f
    sdiv w10, w10, w11
    sxtw x10, w10
    alu_tail
1:  mov x10, #-1
    alu_tail
.gadget rv_divuw_rr
    alu_rr_head
    cbz w11, 1f
    udiv w10, w10, w11
    sxtw x10, w10
    alu_tail
1:  mov x10, #-1
    alu_tail
.gadget rv_remw_rr
    alu_rr_head
    cbz w11, 1f
    sdiv w12, w10, w11
    msub w10, w12, w11, w10
1:  sxtw x10, w10
    alu_tail
.gadget rv_remuw_rr
    alu_rr_head
    cbz w11, 1f
    udiv w12, w10, w11
    msub w10, w12, w11, w10
1:  sxtw x10, w10
    alu_tail

// ---- Zba, Zbb, Zbs, Zicond (RVA23U64's scalar bit-manipulation) -----------
// Same streams as above: reg-reg [gadget][rd_off][rs1_off][rs2_off], reg-imm
// and unary [gadget][rd_off][rs1_off][imm] (unary ops ignore the imm).
// x10 = rs1, x11 = rs2 or imm on entry; the result goes back in x10.
.macro rv_rr name, insn:vararg
.gadget rv_\name\()_rr
    alu_rr_head
    \insn
    alu_tail
.endm
.macro rv_ri name, insn:vararg
.gadget rv_\name\()_ri
    alu_head
    \insn
    alu_tail
.endm

// Zba: shNadd rd = rs2 + (rs1 << N); the .uw forms take rs1's low word,
// zero-extended; slli.uw shifts that word left by the immediate.
rv_rr sh1add, add x10, x11, x10, lsl #1
rv_rr sh2add, add x10, x11, x10, lsl #2
rv_rr sh3add, add x10, x11, x10, lsl #3
rv_rr add_uw, add x10, x11, w10, uxtw
rv_rr sh1add_uw, add x10, x11, w10, uxtw #1
rv_rr sh2add_uw, add x10, x11, w10, uxtw #2
rv_rr sh3add_uw, add x10, x11, w10, uxtw #3
.gadget rv_slli_uw_ri
    alu_head
    mov w10, w10
    lsl x10, x10, x11
    alu_tail

// Zbb
rv_rr andn, bic x10, x10, x11
rv_rr orn, orn x10, x10, x11
rv_rr xnor, eon x10, x10, x11
rv_ri clz, clz x10, x10
rv_ri clzw, clz w10, w10
.gadget rv_ctz_ri
    alu_head
    rbit x10, x10
    clz x10, x10
    alu_tail
.gadget rv_ctzw_ri
    alu_head
    rbit w10, w10
    clz w10, w10
    alu_tail
.gadget rv_cpop_ri
    alu_head
    fmov d0, x10
    cnt v0.8b, v0.8b
    addv b0, v0.8b
    fmov w10, s0
    alu_tail
.gadget rv_cpopw_ri
    alu_head
    mov w10, w10
    fmov d0, x10
    cnt v0.8b, v0.8b
    addv b0, v0.8b
    fmov w10, s0
    alu_tail
rv_ri sext_b, sxtb x10, w10
rv_ri sext_h, sxth x10, w10
rv_ri zext_h, uxth w10, w10
rv_ri rev8, rev x10, x10
.gadget rv_orc_b_ri
    alu_head
    fmov d0, x10
    cmtst v0.8b, v0.8b, v0.8b
    fmov x10, d0
    alu_tail
.irp op, max,maxu,min,minu
.gadget rv_\op\()_rr
    alu_rr_head
    cmp x10, x11
    .ifc \op, max
    csel x10, x10, x11, gt
    .endif
    .ifc \op, maxu
    csel x10, x10, x11, hi
    .endif
    .ifc \op, min
    csel x10, x10, x11, lt
    .endif
    .ifc \op, minu
    csel x10, x10, x11, lo
    .endif
    alu_tail
.endr
// rotates: AArch64 has only ror (by register, mod the width); rol by n is
// ror by -n.
.gadget rv_rol_rr
    alu_rr_head
    neg x11, x11
    ror x10, x10, x11
    alu_tail
rv_rr ror, ror x10, x10, x11
rv_ri ror, ror x10, x10, x11
.gadget rv_rolw_rr
    alu_rr_head
    neg w11, w11
    ror w10, w10, w11
    sxtw x10, w10
    alu_tail
.gadget rv_rorw_rr
    alu_rr_head
    ror w10, w10, w11
    sxtw x10, w10
    alu_tail
.gadget rv_rorw_ri
    alu_head
    ror w10, w10, w11
    sxtw x10, w10
    alu_tail

// Zbs: the bit index is rs2 (or the immediate) mod 64.
.irp form, rr,ri
.gadget rv_bclr_\form
    .ifc \form, rr
    alu_rr_head
    .else
    alu_head
    .endif
    mov x12, #1
    lsl x12, x12, x11
    bic x10, x10, x12
    alu_tail
.gadget rv_bset_\form
    .ifc \form, rr
    alu_rr_head
    .else
    alu_head
    .endif
    mov x12, #1
    lsl x12, x12, x11
    orr x10, x10, x12
    alu_tail
.gadget rv_binv_\form
    .ifc \form, rr
    alu_rr_head
    .else
    alu_head
    .endif
    mov x12, #1
    lsl x12, x12, x11
    eor x10, x10, x12
    alu_tail
.gadget rv_bext_\form
    .ifc \form, rr
    alu_rr_head
    .else
    alu_head
    .endif
    lsr x10, x10, x11
    and x10, x10, #1
    alu_tail
.endr

// Zicond: czero.eqz rd = rs2 == 0 ? 0 : rs1; czero.nez rd = rs2 != 0 ? 0 : rs1.
.gadget rv_czero_eqz_rr
    alu_rr_head
    cmp x11, #0
    csel x10, xzr, x10, eq
    alu_tail
.gadget rv_czero_nez_rr
    alu_rr_head
    cmp x11, #0
    csel x10, xzr, x10, ne
    alu_tail

/* ---- Constants ---------------------------------------------------------- */

/* [rd offset][value] */
.gadget rv_li
    ldp x9, x10, [_ip]
    str x10, [_cpu, x9]
    gret 2

/* [rd offset][delta]: rd = entry pc + delta (auipc, and the link of a jal) */
.gadget rv_pcrel
    ldp x9, x10, [_ip]
    add x10, _pc, x10
    str x10, [_cpu, x9]
    gret 2

/* fence: a full barrier, as TCG's tcg_gen_mb(TCG_MO_ALL | TCG_BAR_SC) */
.gadget rv_fence
    dmb ish
    gret

/* ---- Loads and stores ----------------------------------------------------
 *
 * Stream: [gadget][reg offset][rs1 offset][imm][pc delta][insn]
 *
 * The softmmu fast path, as TCG's own backends inline it: index this TB's
 * fast table by the page number (folded, CPU_TLB_INDEX_FOLD), compare the
 * entry's tag with the address, and on a match the entry's addend turns the
 * guest address into a host one. The tag is compared with the address's page
 * AND its low alignment bits, so only an aligned access to a page with no
 * flags set hits; a misaligned one, MMIO, a watched or not-yet-dirty page
 * and a real miss all leave by the slow path, which is cputlb's.
 *
 * The slow path may raise a guest exception and not return. It is told the
 * insn's pc and opcode, which it stores first, so the CPU state is exact
 * there with nothing to unwind: the last two operands are read only then.
 */
#define TLB_FOLD        8       /* CPU_TLB_INDEX_FOLD */
#define TLB_SHIFT       7       /* TARGET_PAGE_BITS - CPU_TLB_ENTRY_BITS */
#define TLBE_READ       0
#define TLBE_WRITE      8
#define TLBE_ADDEND     24

.macro rv_load name, tagmask, insn:vararg
.gadget rv_\name
    ldp x9, x10, [_ip]          /* rd offset, rs1 offset */
    ldr x11, [_ip, #16]         /* imm */
    ldr x10, [_cpu, x10]
    ldp x12, x13, [_tlb]        /* mask, table */
    add x7, x10, x11            /* guest address */
    eor x14, x7, x7, lsr #TLB_FOLD
    and x12, x12, x14, lsr #TLB_SHIFT
    add x13, x13, x12
    ldr x14, [x13, #TLBE_READ]
    ldr x15, [x13, #TLBE_ADDEND]
    and x16, x7, #\tagmask
    cmp x14, x16
    b.ne 1f
    \insn, [x7, x15]
    str x11, [_cpu, x9]
    gret 5
1:  ldp x2, x3, [_ip, #24]      /* pc delta, insn */
    mov x0, _cpu
    mov x1, x7
    add x2, _pc, x2
    bl SYM(aok_rv_helper_\name)
    ldr x9, [_ip]
    str x0, [_cpu, x9]
    gret 5
.endm

rv_load lb,  0xfffffffffffff000, ldrsb x11
rv_load lbu, 0xfffffffffffff000, ldrb w11
rv_load lh,  0xfffffffffffff001, ldrsh x11
rv_load lhu, 0xfffffffffffff001, ldrh w11
rv_load lw,  0xfffffffffffff003, ldrsw x11
rv_load lwu, 0xfffffffffffff003, ldr w11
rv_load ld,  0xfffffffffffff007, ldr x11

.macro rv_store name, tagmask, insn:vararg
.gadget rv_\name
    ldp x9, x10, [_ip]          /* rs2 offset, rs1 offset */
    ldr x11, [_ip, #16]         /* imm */
    ldr x10, [_cpu, x10]
    ldp x12, x13, [_tlb]
    add x7, x10, x11
    ldr x11, [_cpu, x9]         /* the value */
    eor x14, x7, x7, lsr #TLB_FOLD
    and x12, x12, x14, lsr #TLB_SHIFT
    add x13, x13, x12
    ldr x14, [x13, #TLBE_WRITE]
    ldr x15, [x13, #TLBE_ADDEND]
    and x16, x7, #\tagmask
    cmp x14, x16
    b.ne 1f
    \insn, [x7, x15]
    gret 5
1:  ldp x3, x4, [_ip, #24]      /* pc delta, insn */
    mov x0, _cpu
    mov x1, x7
    mov x2, x11
    add x3, _pc, x3
    bl SYM(aok_rv_helper_\name)
    gret 5
.endm

rv_store sb, 0xfffffffffffff000, strb w11
rv_store sh, 0xfffffffffffff001, strh w11
rv_store sw, 0xfffffffffffff003, str w11
rv_store sd, 0xfffffffffffff007, str x11

/* ---- Control flow --------------------------------------------------------
 *
 * A conditional branch ends its TB and leaves it by one of two jumps:
 * [gadget][rs1 offset][rs2 offset][taken delta][taken slot][fall delta][fall slot]
 * See aok_gadget_goto for what a delta and a slot are.
 */
.macro rv_branch name, cond
.gadget rv_b\name
    ldp x9, x10, [_ip]
    ldr x9, [_cpu, x9]
    ldr x10, [_cpu, x10]
    cmp x9, x10
    b.\cond 1f
    ldp x9, x10, [_ip, #32]
    b SYM(aok_goto_tail)
1:  ldp x9, x10, [_ip, #16]
    b SYM(aok_goto_tail)
.endm

rv_branch eq, eq
rv_branch ne, ne
rv_branch lt, lt
rv_branch ge, ge
rv_branch ltu, lo
rv_branch geu, hs

/*
 * jalr: [rd offset][rs1 offset][imm][link delta]. The target is computed
 * from rs1 before the link is written, since rd may be rs1. Leaves env->pc
 * set; the stream goes on to find the TB there.
 */
.gadget rv_jalr
    ldp x9, x10, [_ip]
    ldp x11, x12, [_ip, #16]
    ldr x10, [_cpu, x10]
    add x12, _pc, x12
    add x10, x10, x11
    bic x10, x10, #1
    str x12, [_cpu, x9]
    str x10, [_pcp]
    gret 4
