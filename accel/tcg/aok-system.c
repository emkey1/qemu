/*
 * AOK gadgets: what a system emulator adds.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/notify.h"
#include "hw/core/cpu.h"
#include "hw/nvram/fw_cfg.h"
#include "system/system.h"
#include "system/tcg.h"
#include "accel/tcg/cpu-ops.h"
#include "accel/tcg/aok.h"
#include "qemu/target-info.h"

/*
 * A guest cannot tell which engine runs it, and neither can whoever is
 * sitting at it. So a machine whose CPUs have a front end, with the gadgets
 * on, says so in a fw_cfg file, opt/aok/engine: one line, "AOK gadgets
 * (ARCH)". In a Linux guest that is
 * /sys/firmware/qemu_fw_cfg/by_name/opt/aok/engine/raw (the qemu_fw_cfg
 * module, and root). It is absent with QEMU_AOK=0 and for a guest
 * architecture the gadgets do not know.
 */
char *aok_engine_line(void)
{
    if (!tcg_enabled() || !aok_enabled || !first_cpu ||
        !first_cpu->cc->tcg_ops->aok_translate_code) {
        return NULL;
    }
    return g_strdup_printf("AOK gadgets (%s)", target_name());
}

static void aok_machine_done(Notifier *notifier, void *data)
{
    FWCfgState *fw_cfg = fw_cfg_find();
    g_autofree char *line = aok_engine_line();

    if (fw_cfg && line) {
        char *file = g_strdup_printf("%s\n", line);

        fw_cfg_add_file(fw_cfg, "opt/aok/engine", file, strlen(file));
    }
}

static Notifier aok_machine_done_notifier = { .notify = aok_machine_done };

static void __attribute__((constructor)) aok_system_init(void)
{
    qemu_add_machine_init_done_notifier(&aok_machine_done_notifier);
}
