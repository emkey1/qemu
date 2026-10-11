/*
 * AOK gadgets for RISC-V guests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RISCV_AOK_H
#define RISCV_AOK_H

int riscv_aok_translate_code(CPUState *cs, TranslationBlock *tb,
                             int *max_insns, vaddr pc, void *host_pc);

#endif
