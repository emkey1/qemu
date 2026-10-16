/*
 * tpm_crb_sysbus.c - QEMU's TPM CRB interface emulator
 *
 * Copyright (c) 2018 Red Hat, Inc.
 *
 * Authors:
 *   Marc-André Lureau <marcandre.lureau@redhat.com>
 *   Joelle van Dyne <j@getutm.app>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 * tpm_crb is a device for TPM 2.0 Command Response Buffer (CRB) Interface
 * as defined in TCG PC Client Platform TPM Profile (PTP) Specification
 * Family “2.0” Level 00 Revision 01.03 v22
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/acpi/tpm.h"
#include "hw/core/qdev-properties.h"
#include "migration/vmstate.h"
#include "tpm_prop.h"
#include "hw/core/sysbus.h"
#include "qom/object.h"
#include "tpm_crb.h"

struct TPMCRBStateSysBus {
    /*< private >*/
    SysBusDevice parent_obj;

    /*< public >*/
    TPMCRBState state;
    MemoryRegion container;
    uint64_t baseaddr;
    uint64_t size;
};

OBJECT_DECLARE_SIMPLE_TYPE(TPMCRBStateSysBus, TPM_CRB_SYSBUS)

static void tpm_crb_sysbus_request_completed(TPMIf *ti, int ret)
{
    TPMCRBStateSysBus *s = TPM_CRB_SYSBUS(ti);

    return tpm_crb_request_completed(&s->state, ret);
}

static enum TPMVersion tpm_crb_sysbus_get_tpm_version(TPMIf *ti)
{
    TPMCRBStateSysBus *s = TPM_CRB_SYSBUS(ti);

    return tpm_crb_get_version(&s->state);
}

static int tpm_crb_sysbus_pre_save(void *opaque)
{
    TPMCRBStateSysBus *s = opaque;

    return tpm_crb_pre_save(&s->state);
}

static bool tpm_crb_sysbus_chunk_needed(void *opaque)
{
    TPMCRBStateSysBus *s = opaque;

    return tpm_crb_chunk_needed(&s->state);
}

static bool tpm_crb_sysbus_chunk_post_load(void *opaque, int version_id,
                                           Error **errp)
{
    TPMCRBStateSysBus *s = opaque;

    return tpm_crb_chunk_post_load(&s->state, errp);
}

static const VMStateDescription vmstate_tpm_crb_sysbus_chunk = {
    .name = "tpm-crb-sysbus/chunk",
    .version_id = 0,
    .needed = tpm_crb_sysbus_chunk_needed,
    .post_load_errp = tpm_crb_sysbus_chunk_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_GBYTEARRAY(state.command_buffer, TPMCRBStateSysBus, 0),
        VMSTATE_GBYTEARRAY(state.response_buffer, TPMCRBStateSysBus, 0),
        VMSTATE_UINT32(state.response_offset, TPMCRBStateSysBus),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_tpm_crb_sysbus = {
    .name = "tpm-crb-sysbus",
    .pre_save = tpm_crb_sysbus_pre_save,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(state.regs, TPMCRBStateSysBus, TPM_CRB_R_MAX),
        VMSTATE_END_OF_LIST(),
    },
    .subsections = (const VMStateDescription * const []) {
        &vmstate_tpm_crb_sysbus_chunk,
        NULL,
    }
};

static const Property tpm_crb_sysbus_properties[] = {
    DEFINE_PROP_TPMBE("tpmdev", TPMCRBStateSysBus, state.tpmbe),
    DEFINE_PROP_UINT64("x-baseaddr", TPMCRBStateSysBus,
                       baseaddr, TPM_CRB_ADDR_BASE),
    DEFINE_PROP_UINT64("x-size", TPMCRBStateSysBus,
                       size, TPM_CRB_ADDR_SIZE),
    DEFINE_PROP_BOOL("cap-chunk", TPMCRBStateSysBus, state.cap_chunk, true),
    DEFINE_PROP_BOOL("x-allow-chunk-migration", TPMCRBStateSysBus,
                     state.allow_chunk_migration, true),
};

static void tpm_crb_sysbus_reset(DeviceState *dev)
{
    TPMCRBStateSysBus *s = TPM_CRB_SYSBUS(dev);

    return tpm_crb_reset(&s->state, s->baseaddr);
}

static void tpm_crb_sysbus_realizefn(DeviceState *dev, Error **errp)
{
    TPMCRBStateSysBus *s = TPM_CRB_SYSBUS(dev);

    if (!tpm_find()) {
        error_setg(errp, "at most one TPM device is permitted");
        return;
    }

    if (!s->state.tpmbe) {
        error_setg(errp, "'tpmdev' property is required");
        return;
    }

    if (tpm_crb_sysbus_get_tpm_version(TPM_IF(s)) != TPM_VERSION_2_0) {
        error_setg(errp, "TPM CRB only supports TPM 2.0 backends");
        return;
    }

    if (!tpm_crb_init(OBJECT(s), &s->state, errp)) {
        return;
    }

    /* one window, as the platform bus maps it: registers, then the buffer */
    memory_region_init(&s->container, OBJECT(s), "tpm-crb",
                       TPM_CRB_ADDR_SIZE);
    memory_region_add_subregion(&s->container, 0, &s->state.mmio);
    memory_region_add_subregion(&s->container, sizeof(s->state.regs),
                                &s->state.cmdmem);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->container);
}

static void tpm_crb_sysbus_unrealizefn(DeviceState *dev)
{
    TPMCRBStateSysBus *s = TPM_CRB_SYSBUS(dev);

    tpm_crb_fini(&s->state);
}

static void tpm_crb_sysbus_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    TPMIfClass *tc = TPM_IF_CLASS(klass);

    device_class_set_props(dc, tpm_crb_sysbus_properties);
    dc->vmsd  = &vmstate_tpm_crb_sysbus;
    tc->model = TPM_MODEL_TPM_CRB;
    dc->realize = tpm_crb_sysbus_realizefn;
    dc->unrealize = tpm_crb_sysbus_unrealizefn;
    dc->user_creatable = true;
    device_class_set_legacy_reset(dc, tpm_crb_sysbus_reset);
    tc->request_completed = tpm_crb_sysbus_request_completed;
    tc->get_version = tpm_crb_sysbus_get_tpm_version;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo tpm_crb_sysbus_info = {
    .name = TYPE_TPM_CRB_SYSBUS,
    .parent = TYPE_DYNAMIC_SYS_BUS_DEVICE,
    .instance_size = sizeof(TPMCRBStateSysBus),
    .class_init  = tpm_crb_sysbus_class_init,
    .interfaces = (const InterfaceInfo[]) {
        { TYPE_TPM_IF },
        { }
    }
};

static void tpm_crb_sysbus_register(void)
{
    type_register_static(&tpm_crb_sysbus_info);
}

type_init(tpm_crb_sysbus_register)
