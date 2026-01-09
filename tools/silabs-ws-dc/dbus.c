/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2026 Silicon Laboratories Inc. (www.silabs.com)
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of the Silicon Labs Master Software License
 * Agreement (MSLA) available at [1].  This software is distributed to you in
 * Object Code format and/or Source Code format and is governed by the sections
 * of the MSLA applicable to Object Code, Source Code and Modified Open Source
 * Code. By using this software, you agree to the terms of the MSLA.
 *
 * [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
 */
#include <systemd/sd-bus.h>
#include <errno.h>

#include "common/dbus.h"
#include "common/log.h"

#include "dbus.h"

const struct sd_bus_vtable dc_dbus_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_SIGNAL("TargetDiscovered", "ayay", 0),
    SD_BUS_VTABLE_END,
};

void dc_dbus_emit_target_discovered(const uint8_t eui64[8], const uint8_t target_id[SL_DC_ID_LEN])
{
    struct dbus_ctx *dbus = dbus_get_ctx();
    sd_bus_message *msg;
    int ret;

    if (!dbus)
        return;

    ret = sd_bus_message_new_signal(dbus->dbus, &msg, dbus->path, dbus->interface, "TargetDiscovered");
    if (ret < 0) {
        WARN("sd_bus_message_new_signal: %s", strerror(-ret));
        return;
    }

    sd_bus_message_append_array(msg, 'y', eui64, 8);
    sd_bus_message_append_array(msg, 'y', target_id, SL_DC_ID_LEN);

    ret = sd_bus_send(dbus->dbus, msg, NULL);
    if (ret < 0)
        WARN("sd_bus_send: %s", strerror(-ret));
    sd_bus_message_unref(msg);
}
