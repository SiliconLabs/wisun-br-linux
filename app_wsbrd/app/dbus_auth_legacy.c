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
#include <errno.h>
#include <math.h>

#include "app_wsbrd/app/wsbrd.h"
#include "app_wsbrd/ws/ws_pae_auth.h"
#include "app_wsbrd/ws/ws_pae_controller.h"
#include "app_wsbrd/ws/ws_pae_key_storage.h"
#include "app_wsbrd/ws/ws_pae_lib.h"
#include "common/memutils.h"

#include "dbus_auth.h"

void dbus_message_append_supp(sd_bus_message *m, const char *property, const void *_supp)
{
    const supp_entry_t *supp = _supp;

    dbus_message_open_info(m, property, "is_authenticated", "b");
    sd_bus_message_append_basic(m, 'b', (int[1]){ true });
    dbus_message_close_info(m, property);
    if (ws_common_is_valid_nr(supp->sec_keys.node_role)) {
        dbus_message_open_info(m, property, "node_role", "y");
        sd_bus_message_append(m, "y", supp->sec_keys.node_role);
        dbus_message_close_info(m, property);
    }
}

int dbus_get_nodes(sd_bus *bus, const char *path, const char *interface,
                   const char *property, sd_bus_message *reply,
                   void *userdata, sd_bus_error *ret_error)
{
    const struct ws_neigh *neighbor_info;
    struct wsbr_ctxt *ctxt = userdata;
    int len_pae;
    uint8_t eui64_pae[4096][8];
    supp_entry_t *supp;

    len_pae = ws_pae_auth_supp_list(ctxt->net_if.id, eui64_pae, sizeof(eui64_pae));

    sd_bus_message_open_container(reply, 'a', "(aya{sv})");
    dbus_message_append_node_br(reply, property, ctxt);

    for (int i = 0; i < len_pae; i++) {
        neighbor_info = ws_neigh_get(&ctxt->net_if.ws_info.neighbor_storage,
                                     &EUI64_FROM_BUF(eui64_pae[i]));
        if (ws_pae_key_storage_supp_exists(eui64_pae[i]))
            supp = ws_pae_key_storage_supp_read(NULL, eui64_pae[i], NULL, NULL, NULL);
        else
            supp = NULL;
        dbus_message_append_node(reply, property, &EUI64_FROM_BUF(eui64_pae[i]),
                                 false, supp, neighbor_info);
        if (supp)
            free(supp);
    }
    sd_bus_message_close_container(reply);
    return 0;
}
