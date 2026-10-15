/*
 * AOK gadgets: which engine runs a machine, in its device tree.
 *
 * Only targets that have device trees build this (CONFIG_DEVICE_TREE), as
 * with system/device_tree.c: a machine without one, the 68k Macintosh for
 * one, would not link against the helpers.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "system/device_tree.h"
#include "accel/tcg/aok.h"

/*
 * The property "aok,engine" of /chosen, which a Linux guest has as
 * /proc/device-tree/chosen/aok,engine with no driver at all. Called by the
 * machine when its tree is otherwise complete.
 */
void aok_fdt_announce(void *fdt)
{
    g_autofree char *line = aok_engine_line();

    if (fdt && line) {
        qemu_fdt_add_path(fdt, "/chosen");
        qemu_fdt_setprop_string(fdt, "/chosen", "aok,engine", line);
    }
}
