/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef WSBR_DBUS_H
#define WSBR_DBUS_H
#include <systemd/sd-bus.h>

struct wsbr_ctxt;

sd_bus *dbus_register(struct wsbr_ctxt *ctxt);
int dbus_process(struct wsbr_ctxt *ctxt, sd_bus *bus);

#endif
