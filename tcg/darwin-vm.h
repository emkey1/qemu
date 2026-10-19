/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The Mach VM calls the code buffer is managed with. <mach/mach_vm.h>
 * declares them, but in the iOS SDK it is only an #error, so they are
 * declared here instead.
 */

#ifndef TCG_DARWIN_VM_H
#define TCG_DARWIN_VM_H

#include <mach/mach.h>
#include <mach/vm_purgable.h>

kern_return_t mach_vm_purgable_control(vm_map_t target_task,
                                       mach_vm_address_t address,
                                       vm_purgable_t control,
                                       int *state);

kern_return_t mach_vm_remap(vm_map_t target_task,
                            mach_vm_address_t *target_address,
                            mach_vm_size_t size,
                            mach_vm_offset_t mask,
                            int flags,
                            vm_map_t src_task,
                            mach_vm_address_t src_address,
                            boolean_t copy,
                            vm_prot_t *cur_protection,
                            vm_prot_t *max_protection,
                            vm_inherit_t inheritance);

#endif
