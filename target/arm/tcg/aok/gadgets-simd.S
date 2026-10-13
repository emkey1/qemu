/*
 * AOK gadgets for AArch64 guests: floating point and Advanced SIMD.
 *
 * The guest's instruction set is the host's, so an FP or SIMD instruction is
 * computed by itself: the same encoding with its registers renumbered, on the
 * host's FP unit under the guest's FPCR. Nothing may be assembled at run
 * time, so every encoding there is has been assembled here, as a thunk of
 * two instructions,
 *
 *     <the instruction, with Rd = 0, Rn = 1, Rm = 2, Ra = 3>
 *     ret
 *
 * in tables indexed by the bits of the encoding that are not registers. A
 * gadget is then one of a few shapes -- which registers are loaded from
 * CPUARMState, and what is stored back -- and takes the thunk's address as an
 * operand. The translator (translate-a64.c, "Floating point and SIMD")
 * decides which encodings exist for the guest's CPU, and only those are ever
 * called: a table also holds the thunks of encodings that are not allocated,
 * and of ones this host may not have.
 *
 * The destination is loaded too, whether or not the instruction reads it:
 * many do (the accumulating ones, an insert), and one shape for both is
 * worth the load.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define A64_GADGET_HOST qemu
#define AOK_ASM_OWN_GADGET
#include "accel/tcg/aok-asm.h"
#include "aok-arm-asm.h"

    .text

/* ---- The guest's FP environment ---------------------------------------------
 *
 * A gadget whose instruction rounds, or raises a flag, or saturates (FPSR.QC)
 * begins with fp_on. The first one of a run gives the host's FPCR the
 * guest's rounding mode, flush-to-zero and default-NaN bits -- the
 * translator leaves FP to TCG while the guest's FPCR has any other -- and
 * clears the host's FPSR, which from then on holds what the run has raised.
 * aok_fp_end (aok-asm.h) undoes both before any C runs.
 */
.macro fp_on
    cbnz _fpact, 8f
    bl SYM(aok_a64_fp_on)
8:
.endm

    .balign 16
    .globl SYM(aok_a64_fp_on)
SYM(aok_a64_fp_on):
    ldr w16, [_cpu, #AOK_A64_ENV_FPCR]
    msr fpcr, x16
    msr fpsr, xzr
    mov _fpact, #1
    ret

/* ---- The shapes -----------------------------------------------------------------
 *
 * Operands are byte offsets into CPUARMState, of V registers or of X
 * registers (the zero and sink slots for XZR), and last the thunk. A NAME_fp
 * twin begins with fp_on.
 */
.macro shapes fp, sfx
/* v2: [vd][vn][thunk] */
.gadget v2\sfx
    ldp x9, x10, [_ip]
    ldr x12, [_ip, #16]
    \fp
    ldr q0, [_cpu, x9]
    ldr q1, [_cpu, x10]
    blr x12
    str q0, [_cpu, x9]
    gret 3

/* v3: [vd][vn][vm][thunk] */
.gadget v3\sfx
    ldp x9, x10, [_ip]
    ldp x11, x12, [_ip, #16]
    \fp
    ldr q0, [_cpu, x9]
    ldr q1, [_cpu, x10]
    ldr q2, [_cpu, x11]
    blr x12
    str q0, [_cpu, x9]
    gret 4

/* v4: [vd][vn][vm][va][thunk] */
.gadget v4\sfx
    ldp x9, x10, [_ip]
    ldp x11, x13, [_ip, #16]
    ldr x12, [_ip, #32]
    \fp
    ldr q0, [_cpu, x9]
    ldr q1, [_cpu, x10]
    ldr q2, [_cpu, x11]
    ldr q3, [_cpu, x13]
    blr x12
    str q0, [_cpu, x9]
    gret 5

/* xv: [xd][vn][thunk], an X or W register from a V one */
.gadget xv\sfx
    ldp x9, x10, [_ip]
    ldr x12, [_ip, #16]
    \fp
    ldr q1, [_cpu, x10]
    blr x12
    str x0, [_cpu, x9]
    gret 3

/* vx: [vd][xn][thunk], a V register from an X or W one */
.gadget vx\sfx
    ldp x9, x10, [_ip]
    ldr x12, [_ip, #16]
    \fp
    ldr q0, [_cpu, x9]
    ldr x1, [_cpu, x10]
    blr x12
    str q0, [_cpu, x9]
    gret 3
.endm

.macro no_fp
.endm
shapes no_fp,
shapes fp_on, _fp

/*
 * tbl and tbx: [vd][vm][thunk][vn][vn + 1][vn + 2][vn + 3], the table in
 * host v4-v7. The registers of a shorter table are loaded all the same, from
 * whatever offsets the translator gave.
 */
.gadget vtbl
    ldp x9, x11, [_ip]
    ldp x12, x13, [_ip, #16]
    ldp x14, x15, [_ip, #32]
    ldr x10, [_ip, #48]
    ldr q0, [_cpu, x9]
    ldr q2, [_cpu, x11]
    ldr q4, [_cpu, x13]
    ldr q5, [_cpu, x14]
    ldr q6, [_cpu, x15]
    ldr q7, [_cpu, x10]
    blr x12
    str q0, [_cpu, x9]
    gret 7

/* A constant: [vd][low half][high half] */
.gadget vconst
    ldp x9, x10, [_ip]
    ldr x11, [_ip, #16]
    add x9, _cpu, x9
    stp x10, x11, [x9]
    gret 3

/*
 * orr and bic with an immediate: [vd][low half][high half], the mask to OR
 * in, or the one to AND with (for a 64-bit vector, zero above).
 */
.gadget vorr_const
    ldp x9, x10, [_ip]
    ldr x11, [_ip, #16]
    add x9, _cpu, x9
    ldp x12, x13, [x9]
    orr x12, x12, x10
    orr x13, x13, x11
    stp x12, x13, [x9]
    gret 3
.gadget vand_const
    ldp x9, x10, [_ip]
    ldr x11, [_ip, #16]
    add x9, _cpu, x9
    ldp x12, x13, [x9]
    and x12, x12, x10
    and x13, x13, x11
    stp x12, x13, [x9]
    gret 3

/*
 * Compares and selects, which meet the integer flags.
 * vcmp: [vn][vm][thunk]: fcmp and fcmpe, the flags stored.
 * vccmp, vccmp_nf: the same for fccmp, which reads them first.
 * vcsel, vcsel_nf: [vd][vn][vm][thunk]: fcsel, which only reads them.
 * (_nf: the host's flags are the guest's already; translate-a64.c, Ctx.nf.)
 */
.gadget vcmp
    ldp x10, x11, [_ip]
    ldr x12, [_ip, #16]
    fp_on
    ldr q1, [_cpu, x10]
    ldr q2, [_cpu, x11]
    blr x12
    store_flags
    gret 3
.macro vccmp name, load
.gadget \name
    ldp x10, x11, [_ip]
    ldr x12, [_ip, #16]
    fp_on
    ldr q1, [_cpu, x10]
    ldr q2, [_cpu, x11]
    \load
    blr x12
    store_flags
    gret 3
.endm
vccmp vccmp, load_flags
vccmp vccmp_nf, no_fp
.macro vcsel name, load
.gadget \name
    ldp x9, x10, [_ip]
    ldp x11, x12, [_ip, #16]
    ldr q1, [_cpu, x10]
    ldr q2, [_cpu, x11]
    \load
    blr x12
    str q0, [_cpu, x9]
    gret 4
.endm
vcsel vcsel, load_flags
vcsel vcsel_nf, no_fp

/* crc32: [xd][xn][xm][thunk], on the host's own instruction */
.gadget xcrc
    ldp x9, x10, [_ip]
    ldp x11, x12, [_ip, #16]
    ldr x1, [_cpu, x10]
    ldr x2, [_cpu, x11]
    blr x12
    str x0, [_cpu, x9]
    gret 4

/* ---- The thunks ------------------------------------------------------------------
 *
 * thunks NAME, COUNT, EXPR: aok_a64_thunks_NAME, COUNT thunks of eight bytes,
 * the i-th the instruction EXPR(i). Rd is 0, Rn 1, Rm 2 and Ra 3 throughout,
 * and a table's index is spelled out where translate-a64.c computes it.
 */
.macro thunks name, count, expr:vararg
    .balign 16
    .globl SYM(aok_a64_thunks_\name)
SYM(aok_a64_thunks_\name):
    .set i, 0
    .rept \count
    .inst \expr
    ret
    .set i, i + 1
    .endr
.endm

#define B(pos)          ((i >> (pos)) & 1)
#define F(pos, len)     ((i >> (pos)) & ((1 << (len)) - 1))
#define RN              (1 << 5)
#define RM              (2 << 16)
#define RA              (3 << 10)

/* Three same, vector: Q U size opcode(5) */
thunks v3same, 512, 0x0e200400 | RN | RM | B(8) << 30 | B(7) << 29 | F(5, 2) << 22 | F(0, 5) << 11
/* Three different, vector: Q U size opcode(4) */
thunks v3diff, 256, 0x0e200000 | RN | RM | B(7) << 30 | B(6) << 29 | F(4, 2) << 22 | F(0, 4) << 12
/* Three same, scalar: U size opcode(5) */
thunks s3same, 256, 0x5e200400 | RN | RM | B(7) << 29 | F(5, 2) << 22 | F(0, 5) << 11
/* Three different, scalar: U size opcode(4) */
thunks s3diff, 128, 0x5e200000 | RN | RM | B(6) << 29 | F(4, 2) << 22 | F(0, 4) << 12
/* Two-register miscellaneous, vector: Q U size opcode(5) */
thunks v2misc, 512, 0x0e200800 | RN | B(8) << 30 | B(7) << 29 | F(5, 2) << 22 | F(0, 5) << 12
/* Two-register miscellaneous, scalar: U size opcode(5) */
thunks s2misc, 256, 0x5e200800 | RN | B(7) << 29 | F(5, 2) << 22 | F(0, 5) << 12
/* Across lanes: Q U size opcode(5) */
thunks vlanes, 512, 0x0e300800 | RN | B(8) << 30 | B(7) << 29 | F(5, 2) << 22 | F(0, 5) << 12
/* Scalar pairwise: U size opcode(5) */
thunks spair, 256, 0x5e300800 | RN | B(7) << 29 | F(5, 2) << 22 | F(0, 5) << 12
/* Copy: scalar Q op imm5 imm4 */
thunks copy, 4096, 0x0e000400 | RN | B(11) << 28 | B(10) << 30 | B(9) << 29 | F(4, 5) << 16 | F(0, 4) << 11
/* Shift by immediate: scalar Q U immh:immb(7) opcode(5) */
thunks shift, 32768, 0x0f000400 | RN | B(14) << 28 | B(13) << 30 | B(12) << 29 | F(5, 7) << 16 | F(0, 5) << 11
/*
 * By element: scalar Q U size L M opcode(4) H, with Rm (four bits) 2. Where
 * M is the register's fifth bit the translator leaves it clear and loads
 * that register as v2.
 */
thunks elem, 4096, 0x0f000000 | RN | RM | B(11) << 28 | B(10) << 30 | B(9) << 29 | F(7, 2) << 22 | B(6) << 21 | B(5) << 20 | F(1, 4) << 12 | B(0) << 11
/* Permute (uzp, trn, zip): Q size opcode(3) */
thunks perm, 64, 0x0e000800 | RN | RM | B(5) << 30 | F(3, 2) << 22 | F(0, 3) << 12
/* ext: Q imm4 */
thunks ext, 32, 0x2e000000 | RN | RM | B(4) << 30 | F(0, 4) << 11
/* tbl, tbx: Q len op, the table from v4, the indices in v2 */
thunks tbl, 16, 0x0e000000 | (4 << 5) | RM | B(3) << 30 | F(1, 2) << 13 | B(0) << 12
/* Scalar FP, one source: type opcode(6) */
thunks fp1, 256, 0x1e204000 | RN | F(6, 2) << 22 | F(0, 6) << 15
/* Scalar FP, two sources: type opcode(4) */
thunks fp2, 64, 0x1e200800 | RN | RM | F(4, 2) << 22 | F(0, 4) << 12
/* Scalar FP, three sources: type o1 o0 */
thunks fp3, 16, 0x1f000000 | RN | RM | RA | F(2, 2) << 22 | B(1) << 21 | B(0) << 15
/* FP and integer: sf type rmode opcode(3) */
thunks fpint, 256, 0x1e200000 | RN | B(7) << 31 | F(5, 2) << 22 | F(3, 2) << 19 | F(0, 3) << 16
/* FP and fixed point: sf type rmode opcode(3) scale(6) */
thunks fpfix, 16384, 0x1e000000 | RN | B(13) << 31 | F(11, 2) << 22 | F(9, 2) << 19 | F(6, 3) << 16 | F(0, 6) << 10
/* fcmp, fcmpe, and with zero: type opcode2<4:3> */
thunks fcmp, 16, 0x1e202000 | RN | RM | F(2, 2) << 22 | F(0, 2) << 3
/* fccmp, fccmpe: type cond op nzcv */
thunks fccmp, 2048, 0x1e200400 | RN | RM | F(9, 2) << 22 | F(5, 4) << 12 | B(4) << 4 | F(0, 4)
/* fcsel: type cond */
thunks fcsel, 64, 0x1e200c00 | RN | RM | F(4, 2) << 22 | F(0, 4) << 12
/* AES: opcode(2), from aese */
thunks aes, 4, 0x4e284800 | RN | F(0, 2) << 12
/* SHA, three registers: opcode(3) */
thunks sha3, 8, 0x5e000000 | RN | RM | F(0, 3) << 12
/* SHA, two registers: opcode(2) */
thunks sha2, 4, 0x5e280800 | RN | F(0, 2) << 12
/* crc32 and crc32c: C sz */
thunks crc, 8, 0x1ac04000 | RN | RM | B(2) << 12 | F(0, 2) << 10 | (B(1) & B(0)) << 31
