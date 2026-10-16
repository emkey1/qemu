/*
 * tpm_crb.c - QEMU's TPM CRB interface emulator
 *
 * Copyright (c) 2018 Red Hat, Inc.
 *
 * Authors:
 *   Marc-André Lureau <marcandre.lureau@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 * tpm_crb is a device for TPM 2.0 Command Response Buffer (CRB) Interface
 * as defined in TCG PC Client Platform TPM Profile (PTP) Specification
 * Family “2.0” Level 00 Revision 01.03 v22
 */

#include "qemu/osdep.h"

#include "qemu/module.h"
#include "qapi/error.h"
#include "system/address-spaces.h"
#include "hw/core/qdev-properties.h"
#include "hw/acpi/tpm.h"
#include "migration/vmstate.h"
#include "system/tpm_backend.h"
#include "system/reset.h"
#include "system/xen.h"
#include "tpm_prop.h"
#include "tpm_ppi.h"
#include "qom/object.h"
#include "tpm_crb.h"

struct CRBState {
    DeviceState parent_obj;

    TPMCRBState state;
    TPMPPI ppi;
};
typedef struct CRBState CRBState;

DECLARE_INSTANCE_CHECKER(CRBState, CRB,
                         TYPE_TPM_CRB)

static void tpm_crb_none_request_completed(TPMIf *ti, int ret)
{
    CRBState *s = CRB(ti);

    tpm_crb_request_completed(&s->state, ret);
}

static enum TPMVersion tpm_crb_none_get_version(TPMIf *ti)
{
    CRBState *s = CRB(ti);

    return tpm_crb_get_version(&s->state);
}

static int tpm_crb_none_pre_save(void *opaque)
{
    CRBState *s = opaque;

    return tpm_crb_pre_save(&s->state);
}

static bool tpm_crb_none_chunk_needed(void *opaque)
{
    CRBState *s = opaque;

    return tpm_crb_chunk_needed(&s->state);
}

static bool tpm_crb_none_chunk_post_load(void *opaque, int version_id,
                                         Error **errp)
{
    CRBState *s = opaque;

    return tpm_crb_chunk_post_load(&s->state, errp);
}

static const VMStateDescription vmstate_tpm_crb_chunk = {
    .name = "tpm-crb/chunk",
    .version_id = 0,
    .needed = tpm_crb_none_chunk_needed,
    .post_load_errp = tpm_crb_none_chunk_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_GBYTEARRAY(state.command_buffer, CRBState, 0),
        VMSTATE_GBYTEARRAY(state.response_buffer, CRBState, 0),
        VMSTATE_UINT32(state.response_offset, CRBState),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_tpm_crb = {
    .name = "tpm-crb",
    .pre_save = tpm_crb_none_pre_save,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(state.regs, CRBState, TPM_CRB_R_MAX),
        VMSTATE_END_OF_LIST(),
    },
    .subsections = (const VMStateDescription * const []) {
        &vmstate_tpm_crb_chunk,
        NULL,
    }
};

static const Property tpm_crb_properties[] = {
    DEFINE_PROP_TPMBE("tpmdev", CRBState, state.tpmbe),
    DEFINE_PROP_BOOL("cap-chunk", CRBState, state.cap_chunk, true),
    DEFINE_PROP_BOOL("x-allow-chunk-migration", CRBState,
                     state.allow_chunk_migration, true),
};

static void tpm_crb_none_reset(void *dev)
{
    CRBState *s = CRB(dev);

    tpm_ppi_reset(&s->ppi);
    tpm_crb_reset(&s->state, TPM_CRB_ADDR_BASE);
}

static void tpm_crb_none_realize(DeviceState *dev, Error **errp)
{
    CRBState *s = CRB(dev);

    if (!tpm_find()) {
        error_setg(errp, "at most one TPM device is permitted");
        return;
    }
    if (!s->state.tpmbe) {
        error_setg(errp, "'tpmdev' property is required");
        return;
    }
    if (!tpm_crb_init(OBJECT(s), &s->state, errp)) {
        return;
    }

    memory_region_add_subregion(get_system_memory(),
        TPM_CRB_ADDR_BASE, &s->state.mmio);
    memory_region_add_subregion(get_system_memory(),
        TPM_CRB_ADDR_BASE + sizeof(s->state.regs), &s->state.cmdmem);

    tpm_ppi_init(&s->ppi, get_system_memory(),
                 TPM_PPI_ADDR_BASE, OBJECT(s));

    if (xen_enabled()) {
        tpm_crb_none_reset(dev);
    } else {
        qemu_register_reset(tpm_crb_none_reset, dev);
    }
}

static void tpm_crb_none_unrealize(DeviceState *dev)
{
    CRBState *s = CRB(dev);

    tpm_crb_fini(&s->state);
}

static void tpm_crb_none_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    TPMIfClass *tc = TPM_IF_CLASS(klass);

    dc->realize = tpm_crb_none_realize;
    dc->unrealize = tpm_crb_none_unrealize;
    device_class_set_props(dc, tpm_crb_properties);
    dc->vmsd  = &vmstate_tpm_crb;
    dc->user_creatable = true;
    tc->model = TPM_MODEL_TPM_CRB;
    tc->ppi_enabled = true;
    tc->get_version = tpm_crb_none_get_version;
    tc->request_completed = tpm_crb_none_request_completed;

    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo tpm_crb_none_info = {
    .name = TYPE_TPM_CRB,
    /* could be TYPE_SYS_BUS_DEVICE (or LPC etc) */
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(CRBState),
    .class_init  = tpm_crb_none_class_init,
    .interfaces = (const InterfaceInfo[]) {
        { TYPE_TPM_IF },
        { }
    }
};

static void tpm_crb_none_register(void)
{
    type_register_static(&tpm_crb_none_info);
}

type_init(tpm_crb_none_register)
