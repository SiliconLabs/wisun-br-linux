/*
 * SPDX-License-Identifier: LicenseRef-MSLA
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

#include "wsrd.h"

#include "join_state.h"

void join_state_1_enter(struct wsrd *wsrd)
{
    // Entering join state 1 means we probably want a fresh start
    wsrd->ws.pan_id = 0xffff;
    supp_reset(&wsrd->supp);
    wsrd->eapol_target_eui64 = ieee802154_addr_bc;
    wsrd->ws.pan_version = -1;
    ipv6_neigh_clean(&wsrd->ipv6);
    ws_neigh_clean(&wsrd->ws.neigh_table);
    INFO("Join state 1: Select PAN");
    trickle_start(&wsrd->pas_tkl);
    timer_start_rel(NULL, &wsrd->pan_selection_timer, wsrd->config.disc_cfg.Imin_ms);
}

void join_state_1_exit(struct wsrd *wsrd)
{
    BUG_ON(timer_stopped(&wsrd->pas_tkl.timer_interval));

    trickle_stop(&wsrd->pas_tkl);
}
