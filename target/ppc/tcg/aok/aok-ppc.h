/*
 * AOK gadgets for PowerPC guests: the front end's entry point.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TARGET_PPC_AOK_PPC_H
#define TARGET_PPC_AOK_PPC_H

int ppc_aok_translate_code(CPUState *cs, TranslationBlock *tb,
                           int *max_insns, vaddr pc, void *host_pc);

#endif
