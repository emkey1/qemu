/*
 * AOK gadgets for PowerPC guests: what the assembly sources know of
 * CPUPPCState in qemu-system-ppc (a 32-bit target_ulong). translate.c checks
 * each value at build time.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TARGET_PPC_AOK_PPC_ASM_H
#define TARGET_PPC_AOK_PPC_ASM_H

/* gpr[32], four bytes each; then gprh[32], aok_zero, lr and ctr. */
#define AOK_PPC_ENV_GPR      0
#define AOK_PPC_ENV_AOK_ZERO 256
#define AOK_PPC_ENV_LR       260
#define AOK_PPC_ENV_CTR      264

/* crf[8], a uint32_t each holding the field's four bits: LT GT EQ SO. */
#define AOK_PPC_ENV_CRF      268
#define AOK_PPC_CR_LT        8
#define AOK_PPC_CR_GT        4
#define AOK_PPC_CR_EQ        2
#define AOK_PPC_CR_SO        1

/* xer without SO, OV and CA, which are each a target_ulong of 0 or 1. */
#define AOK_PPC_ENV_XER      300
#define AOK_PPC_ENV_SO       304
#define AOK_PPC_ENV_OV       308
#define AOK_PPC_ENV_CA       312
#define AOK_PPC_ENV_OV32     316
#define AOK_PPC_ENV_CA32     320

/*
 * FPSCR (a target_ulong) and the bits of it a gadget reads or writes. It is
 * too far into the state for a load's immediate: a gadget adds the high part
 * first (fpscr_at).
 */
#define AOK_PPC_ENV_FPSCR    71388
#define AOK_PPC_FPSCR_FX     0x80000000
#define AOK_PPC_FPSCR_XX     0x02000000
#define AOK_PPC_FPSCR_FI     0x00020000
#define AOK_PPC_FPSCR_FPRF   0x0001f000     /* C FL FG FE FU; FPCC is FL..FU */
#define AOK_PPC_FPSCR_FPCC   0x0000f000
/* RN, NI and the enables of the exceptions a clean result can raise (XE, UE, OE) */
#define AOK_PPC_FPSCR_SLOW   0x0000006f

#endif
