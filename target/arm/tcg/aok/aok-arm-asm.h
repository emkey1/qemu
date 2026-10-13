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

#endif
