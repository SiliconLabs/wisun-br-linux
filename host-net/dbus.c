/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <systemd/sd-bus.h>

#include "host-common/log.h"
#include "dbus.h"
#include "wsbr.h"

int dbus_get_int(sd_bus *bus, const char *path, const char *interface,
                 const char *property, sd_bus_message *reply,
                 void *userdata, sd_bus_error *ret_error)
{
    int *val = userdata;
    int ret;

    ret = sd_bus_message_append(reply, "u", (uint32_t)*val);
    WARN_ON(ret < 0, "%s", strerror(-ret));
    return 0;
}

int dbus_get_string(sd_bus *bus, const char *path, const char *interface,
               const char *property, sd_bus_message *reply,
               void *userdata, sd_bus_error *ret_error)
{
    char *val = userdata;
    int ret;

    ret = sd_bus_message_append(reply, "s", val);
    WARN_ON(ret < 0, "%s", strerror(-ret));
    return 0;
}

static const sd_bus_vtable dbus_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("WisunNetworkName", "s", dbus_get_string,
                        offsetof(struct wsbr_ctxt, ws_name),
                        SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WisunMode", "u", dbus_get_int,
                        offsetof(struct wsbr_ctxt, ws_mode),
                        SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WisunClass", "u", dbus_get_int,
                        offsetof(struct wsbr_ctxt, ws_class),
                        SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_VTABLE_END
};

void dbus_register(struct wsbr_ctxt *ctxt)
{
    int ret;

    ret = sd_bus_default(&ctxt->dbus);
    if (ret < 0) {
        WARN("DBus not available: %s", strerror(-ret));
        return;
    }
    ret = sd_bus_add_object_vtable(ctxt->dbus, NULL, "/com/silabs/Wisun/BorderRouter",
                                   "com.silabs.Wisun.BorderRouter",
                                   dbus_vtable,
                                   ctxt);
    WARN_ON(ret < 0, "%s: %s", __func__, strerror(-ret));
    ret = sd_bus_request_name(ctxt->dbus, "com.silabs.Wisun.BorderRouter",
                              SD_BUS_NAME_ALLOW_REPLACEMENT | SD_BUS_NAME_REPLACE_EXISTING);
    WARN_ON(ret < 0, "%s: %s", __func__, strerror(-ret));
}

int dbus_process(struct wsbr_ctxt *ctxt)
{
    BUG_ON(!ctxt->dbus);
    sd_bus_process(ctxt->dbus, NULL);
    return 0;
}

int dbus_get_fd(struct wsbr_ctxt *ctxt)
{
    if (ctxt->dbus)
        return sd_bus_get_fd(ctxt->dbus);
    else
        return -1;
}
