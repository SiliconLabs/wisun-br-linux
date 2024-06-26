/*
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
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

#include "common/log.h"

#include "dbus.h"

struct dbus_ctx {
    sd_bus *dbus;
    const char *path;
    const char *interface;
} g_dbus = { };

void dbus_emit_change(const char *property_name)
{
    struct dbus_ctx *dbus_ctx = &g_dbus;
    int ret;

    if (!dbus_ctx->dbus)
        return;
    ret = sd_bus_emit_properties_changed(dbus_ctx->dbus,
                                         dbus_ctx->path,
                                         dbus_ctx->interface,
                                         property_name, NULL);
    if (ret < 0)
        WARN("sd_bus_emit_properties_changed \"%s\": %s", property_name, strerror(-ret));
}

void dbus_register(const char *path, const char *interface,
                   const struct sd_bus_vtable *vtable, void *app_ctxt)
{
    struct dbus_ctx *dbus_ctx = &g_dbus;
    const char *dbus_scope = "undefined";
    const char *env_var;
    char mode = 'A';
    int ret;

    env_var = getenv("DBUS_STARTER_BUS_TYPE");
    if (env_var && !strcmp(env_var, "system"))
        mode = 'S';
    if (env_var && !strcmp(env_var, "user"))
        mode = 'U';
    if (env_var && !strcmp(env_var, "session"))
        mode = 'U';
    if (mode == 'U' || mode == 'A')
        ret = sd_bus_default_user(&dbus_ctx->dbus);
    if (mode == 'S' || (mode == 'A' && ret < 0))
        ret = sd_bus_default_system(&dbus_ctx->dbus);
    if (ret < 0) {
        WARN("DBus not available: %s", strerror(-ret));
        return;
    }

    ret = sd_bus_add_object_vtable(dbus_ctx->dbus, NULL, path, interface, vtable, app_ctxt);
    if (ret < 0) {
        WARN("sd_bus_add_object_vtable: %s", strerror(-ret));
        return;
    }

    ret = sd_bus_request_name(dbus_ctx->dbus, interface,
                              SD_BUS_NAME_ALLOW_REPLACEMENT | SD_BUS_NAME_REPLACE_EXISTING);
    if (ret < 0) {
        WARN("sd_bus_request_name \"%s\": %s", interface, strerror(-ret));
        return;
    }

    dbus_ctx->interface = strdup(interface);
    FATAL_ON(!dbus_ctx->interface, 2, "strdup \"%s\": %m", interface);
    dbus_ctx->path = strdup(path);
    FATAL_ON(!dbus_ctx->path, 2, "strdup \"%s\": %m", path);

    sd_bus_get_scope(dbus_ctx->dbus, &dbus_scope);
    INFO("Successfully registered to %s DBus", dbus_scope);
}

int dbus_process(void)
{
    struct dbus_ctx *dbus_ctx = &g_dbus;

    BUG_ON(!dbus_ctx->dbus);
    sd_bus_process(dbus_ctx->dbus, NULL);
    return 0;
}

int dbus_get_fd(void)
{
    struct dbus_ctx *dbus_ctx = &g_dbus;

    if (!dbus_ctx->dbus)
        return -1;
    return sd_bus_get_fd(dbus_ctx->dbus);
}
