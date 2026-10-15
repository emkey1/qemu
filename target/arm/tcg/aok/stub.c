/*
 * AOK gadgets: a build of the Arm target with no A64 front end.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "aok-arm.h"

int arm_aok_translate_code(CPUState *cs, TranslationBlock *tb,
                           int *max_insns, vaddr pc, void *host_pc)
{
    return 0;
}

void arm_aok_fold_fpsr(CPUState *cs, uint32_t fpsr)
{
}

void arm_aok_fpcr_changed(CPUARMState *env)
{
}
