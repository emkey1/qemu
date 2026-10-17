/*
 * AOK gadgets for x86-64 guests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TARGET_I386_AOK_I386_H
#define TARGET_I386_AOK_I386_H

int x86_aok_translate_code(CPUState *cs, TranslationBlock *tb,
                           int *max_insns, vaddr pc, void *host_pc);
void x86_aok_fold_fpsr(CPUState *cs, uint32_t fpsr);
bool x86_aok_avx512(void);
bool x86_aok_tcg_stop(uint32_t flags, const uint8_t *p, const uint8_t *end);

#endif
