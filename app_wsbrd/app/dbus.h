/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef WSBR_DBUS_H
#define WSBR_DBUS_H

struct wsbr_ctxt;

#ifdef HAVE_LIBSYSTEMD
#include <systemd/sd-bus.h>

extern const struct sd_bus_vtable wsbrd_dbus_vtable[];
#else
static const struct sd_bus_vtable *const wsbrd_dbus_vtable;
#endif

#endif
