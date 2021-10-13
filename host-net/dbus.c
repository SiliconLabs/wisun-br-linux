/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <systemd/sd-bus.h>

#include "host-common/log.h"
#include "dbus.h"
#include "wsbr.h"

static const sd_bus_vtable dbus_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_VTABLE_END
};

sd_bus *dbus_register(struct wsbr_ctxt *ctxt)
{
    sd_bus *bus = NULL;
    int ret;

    ret = sd_bus_default(&bus);
    WARN_ON(ret < 0, "sd_bus_default: %s", strerror(-ret));
    ret = sd_bus_add_object_vtable(bus, NULL, "/com/silabs/Wisun/BorderRouter",
                                   "com.silabs.Wisun.BorderRouter",
                                   dbus_vtable,
                                   ctxt);
    WARN_ON(ret < 0, "sd_bus_add_object_vtable: %s", strerror(-ret));
    ret = sd_bus_request_name(bus, "com.silabs.Wisun.BorderRouter",
                              SD_BUS_NAME_ALLOW_REPLACEMENT | SD_BUS_NAME_REPLACE_EXISTING);
    WARN_ON(ret < 0, "sd_bus_request_name: %s", strerror(-ret));
    return bus;
}

int dbus_process(struct wsbr_ctxt *ctxt, sd_bus *bus)
{
    sd_bus_process(bus, NULL);
    return 0;
}
