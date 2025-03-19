/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2025 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef WSBR_DBUS_AUTH_H
#define WSBR_DBUS_AUTH_H

#include <stdbool.h>
#include <systemd/sd-bus.h>

struct net_if;

int dbus_revoke_group_keys(sd_bus_message *m, void *userdata, sd_bus_error *ret_error, bool do_gtk, bool do_lgtk);
int dbus_install_group_key(sd_bus_message *m, void *userdata, sd_bus_error *ret_error, bool is_lgtk);

void dbus_message_open_info(sd_bus_message *m, const char *property,
                            const char *name, const char *type);
void dbus_message_close_info(sd_bus_message *m, const char *property);
void dbus_message_append_supp(sd_bus_message *m, const char *property, const void *supp);
void dbus_message_append_node(sd_bus_message *m, const char *property,
                              const struct eui64 *eui64,
                              bool is_br, const void *supp,
                              const struct ws_neigh *neighbor);
void dbus_message_append_node_br(sd_bus_message *m, const char *property, struct wsbr_ctxt *ctxt);
int dbus_get_nodes(sd_bus *bus, const char *path, const char *interface,
                   const char *property, sd_bus_message *reply,
                   void *userdata, sd_bus_error *ret_error);

#endif
