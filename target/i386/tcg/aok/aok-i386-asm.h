/*
 * AOK gadgets for x86-64 guests: what the assembly sources know of
 * CPUX86State. translate-x86.c checks each value at build time.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TARGET_I386_AOK_I386_ASM_H
#define TARGET_I386_AOK_I386_ASM_H

/* regs[], eight bytes each: rax rcx rdx rbx rsp rbp rsi rdi r8 ... */
#define AOK_X86_ENV_REGS    0
#define AOK_X86_ENV_RSP     (AOK_X86_ENV_REGS + 4 * 8)
#define AOK_X86_ENV_RBP     (AOK_X86_ENV_REGS + 5 * 8)

/* eflags but for the lazy flags and DF: IF is all a gadget touches. */
#define AOK_X86_ENV_EFLAGS  0x108
#define AOK_X86_IF          0x200

/* The lazy flags: cc_dst, cc_src and cc_src2 (eight bytes each), then cc_op. */
#define AOK_X86_ENV_CC_DST  0x110
#define AOK_X86_ENV_CC_SRC  (AOK_X86_ENV_CC_DST + 8)
#define AOK_X86_ENV_CC_SRC2 (AOK_X86_ENV_CC_DST + 16)
#define AOK_X86_ENV_CC_OP   (AOK_X86_ENV_CC_DST + 24)

/* aok_zero, then aok_tmp[0] and aok_tmp[1] (cpu.h). */
#define AOK_X86_ENV_AOK_ZERO 0x138

/* CC_OP_xxxB: the byte form of each lazy operation; + log2 of the bytes. */
#define AOK_CC_OP_MUL       4
#define AOK_CC_OP_ADD       8
#define AOK_CC_OP_ADC       12
#define AOK_CC_OP_SUB       16
#define AOK_CC_OP_SBB       20
#define AOK_CC_OP_LOGIC     24
#define AOK_CC_OP_INC       28
#define AOK_CC_OP_DEC       32
#define AOK_CC_OP_SHL       36
#define AOK_CC_OP_SAR       40
#define AOK_CC_OP_BMILG     44

#endif
