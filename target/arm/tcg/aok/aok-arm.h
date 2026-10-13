/*
 * AOK gadgets for AArch64 guests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TARGET_ARM_AOK_ARM_H
#define TARGET_ARM_AOK_ARM_H

int arm_aok_translate_code(CPUState *cs, TranslationBlock *tb,
                           int *max_insns, vaddr pc, void *host_pc);
void arm_aok_fold_fpsr(CPUState *cs, uint32_t fpsr);

#endif
