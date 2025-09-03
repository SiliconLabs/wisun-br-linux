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
#include <string.h>

#include "app_wsbrd/app/commandline.h"
#include "app_wsbrd/net/protocol.h"
#include "common/authenticator/authenticator.h"
#include "common/ws/eapol_relay.h"
#include "common/mbedtls_extra.h"
#include "common/string_extra.h"

#include "ws_auth.h"

int ws_auth_revoke_pmk(struct net_if *net_if, const struct eui64 *eui64)
{
    return auth_revoke_pmk(net_if->auth, eui64);
}

int ws_auth_revoke_gtks(struct net_if *net_if, bool is_lgtk, const uint8_t new_gtk[16])
{
    return auth_revoke_gtks(net_if->auth,
                            is_lgtk ? &net_if->auth->lgtk_group : &net_if->auth->gtk_group,
                            new_gtk);
}

int ws_auth_install_gtk(struct net_if *net_if, bool is_lgtk, const uint8_t new_gtk[16])
{
    struct auth_gtk_group *gtk_group;
    int slot;
    int ret;

    gtk_group = is_lgtk ? &net_if->auth->lgtk_group : &net_if->auth->gtk_group;
    slot = auth_gtk_slot_next(auth_gtk_slot_latest(net_if->auth, gtk_group));
    ret = auth_install_gtk(net_if->auth, gtk_group, slot, new_gtk);
    if (!ret && net_if->auth->on_gtk_change)
        net_if->auth->on_gtk_change(net_if->auth, 0, BIT(slot), 0);
    return ret;
}

void ws_auth_update_frame_counter(struct net_if *net_if, int key_index, uint32_t frame_counter)
{
    auth_update_frame_counter(net_if->auth, key_index, frame_counter);
}
