/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2025 Silicon Laboratories Inc. (www.silabs.com)
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
#include <errno.h>

#include "app_wsbrd/app/wsbrd.h"
#include "common/authenticator/authenticator.h"
#include "common/string_extra.h"

#include "dbus_auth.h"

int dbus_revoke_group_keys(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    return sd_bus_error_set_errno(ret_error, ENOTSUP); // TODO
}

int dbus_install_group_key(sd_bus_message *m, void *userdata, sd_bus_error *ret_error, bool is_lgtk)
{
    return sd_bus_error_set_errno(ret_error, ENOTSUP); // TODO
}

void dbus_message_append_supp(sd_bus_message *m, const char *property, const void *_supp)
{
    const struct auth_supp_ctx *supp = _supp;

    if (memzcmp(supp->eap_tls.tls.pmk.key, 32)) {
        dbus_message_open_info(m, property, "is_authenticated", "b");
        sd_bus_message_append_basic(m, 'b', (int[1]){ true });
        dbus_message_close_info(m, property);
    }
    if (ws_common_is_valid_nr(supp->node_role)) {
        dbus_message_open_info(m, property, "node_role", "y");
        sd_bus_message_append(m, "y", supp->node_role);
        dbus_message_close_info(m, property);
    }
}

int dbus_get_nodes(sd_bus *bus, const char *path, const char *interface,
                   const char *property, sd_bus_message *reply,
                   void *userdata, sd_bus_error *ret_error)
{
    struct wsbr_ctxt *ctxt = userdata;
    const struct auth_supp_ctx *supp;
    const struct ws_neigh *neigh;

    sd_bus_message_open_container(reply, 'a', "(aya{sv})");
    dbus_message_append_node_br(reply, property, ctxt);
    SLIST_FOREACH(supp, &ctxt->auth.supplicants, link) {
        neigh = ws_neigh_get(&ctxt->net_if.ws_info.neighbor_storage, &supp->eui64);
        dbus_message_append_node(reply, property, &supp->eui64, false, supp, neigh);
    }
    sd_bus_message_close_container(reply);
    return 0;
}
