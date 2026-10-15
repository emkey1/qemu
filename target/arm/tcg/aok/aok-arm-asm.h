/*
 * AOK gadgets for AArch64 guests: what the assembly sources know of
 * CPUARMState. translate-a64.c checks each value at build time.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TARGET_ARM_AOK_ARM_ASM_H
#define TARGET_ARM_AOK_ARM_ASM_H

/* The flags, four words: CF (0 or 1), VF (bit 31), NF (bit 31), ZF (zero). */
#define AOK_A64_ENV_CF      0x228
#define AOK_A64_ENV_VF      (AOK_A64_ENV_CF + 4)
#define AOK_A64_ENV_NF      (AOK_A64_ENV_CF + 8)
#define AOK_A64_ENV_ZF      (AOK_A64_ENV_CF + 12)

/* x30, the link register. */
#define AOK_A64_ENV_X30     0x130

/* PSTATE's bits other than the flags and DAIF; bit 0 is SP. */
#define AOK_A64_ENV_PSTATE  0x158

/* The V registers: 16 bytes at the start of each 256-byte Z register. */
#define AOK_A64_ENV_V0      0xf40
#define AOK_A64_V_STRIDE    0x100

/* vfp.fpcr: the FPCR bits that govern arithmetic, where the register has them. */
#define AOK_A64_ENV_FPCR    0x31a0

#ifdef __ASSEMBLER__
/*
 * What every file of gadgets here begins with (after aok-asm.h): the name of
 * a gadget, and the guest's flags.
 *
 * iSH-AOK keeps a guest's NZCV as the one word mrs and msr move. QEMU keeps
 * four: CF is 0 or 1, VF and NF have their flag in bit 31, and ZF is zero when
 * Z is set. Neither macro changes the host's own flags, so after store_flags
 * they are still the guest's, which is what a translator relies on when it
 * gives the next conditional gadget its no-reload form. x16 and x17 only.
 */
.macro .gadget name
    .balign 16
    .globl SYM(aok_gadget_a64_\name)
SYM(aok_gadget_a64_\name):
.endm

.macro store_flags
    mrs x17, nzcv
    ubfx w16, w17, #29, #1
    str w16, [_cpu, #AOK_A64_ENV_CF]
    lsl w16, w17, #3
    str w16, [_cpu, #AOK_A64_ENV_VF]
    str w17, [_cpu, #AOK_A64_ENV_NF]
    mvn w16, w17
    and w16, w16, #0x40000000
    str w16, [_cpu, #AOK_A64_ENV_ZF]
.endm

.macro load_flags
    ldr w16, [_cpu, #AOK_A64_ENV_NF]
    ldr w17, [_cpu, #AOK_A64_ENV_ZF]
    and w16, w16, #0x80000000
    cmp w17, #0
    orr w17, w16, #0x40000000
    csel w16, w17, w16, eq
    ldr w17, [_cpu, #AOK_A64_ENV_CF]
    orr w16, w16, w17, lsl #29
    ldr w17, [_cpu, #AOK_A64_ENV_VF]
    lsr w17, w17, #31
    orr w16, w16, w17, lsl #28
    msr nzcv, x16
.endm

/*
 * A way out is aok_gadget_goto's two operands, [pc delta][slot]. Each is its
 * own copy of aok_goto_tail rather than a jump to it, so that each ends in an
 * indirect branch of its own (the RISC-V front end's gadgets-shared.S has
 * why).
 */
.macro a64_leave off
    ldp x9, x10, [_ip, #\off]
    ldr w11, [_exitreq]
    add _pc, _pc, x9
    ldr _ip, [x10]
    str _pc, [_pcp]
    tbnz w11, #31, 7f
    gret AOK_ENTER_WORDS
7:  b SYM(aok_exit_requested)
.endm

/*
 * br, blr, ret: [rn offset][tbi][link delta][flags | cflags << 32][cs_base].
 * The target is read before the link is written, since blr's register may be
 * x30, and has its top byte seen to as TCG's gen_top_byte_ignore does it:
 * tbi 0, as it is; 1, 2, 3, sign-extended from bit 55 where the address is in
 * the half that has TBI (the low one, the high one, both); 4, for a regime
 * with one range, its top byte cleared. Then the lookup (gadgets.S's
 * aok_a64_lookup_pc).
 */
.macro a64_tbi
    cbz x11, 4f
    sbfx x12, x10, #0, #56
    cmp x11, #2
    b.hi 3f
    b.eq 2f
    and x10, x12, x10           /* 1: only where bit 55 is clear */
    b 4f
2:  orr x10, x12, x10           /* 2: only where bit 55 is set */
    b 4f
3:  cmp x11, #4
    csel x10, x12, x10, ne      /* 3: both halves */
    b.ne 4f
    and x10, x10, #0x00ffffffffffffff
4:
.endm

/* The fourteen conditions, in the order of their encodings. */
#define CONDS eq, ne, cs, cc, mi, pl, vs, vc, hi, ls, ge, lt, gt, le

#endif

#endif
