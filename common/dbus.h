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
#ifndef COMMON_DBUS_H
#define COMMON_DBUS_H

struct sd_bus_vtable;

#ifdef HAVE_LIBSYSTEMD

void dbus_register(const char *name, const char *path, const char *interface,
                   const struct sd_bus_vtable *vtable, void *app_ctxt);
int dbus_get_fd(void);
int dbus_process(void);

void dbus_emit_change(const char *property_name);

#else

#include "common/log.h"

static inline void dbus_register(const char *name, const char *path, const char *interface,
                                 const struct sd_bus_vtable *vtable, void *app_ctxt)
{
    WARN("support for DBus is disabled");
}

static inline int dbus_get_fd(void)
{
    return -1;
}

static inline int dbus_process(void)
{
    return 0;
}

static inline void dbus_emit_change(const char *property_name)
{
}

#endif

#endif
