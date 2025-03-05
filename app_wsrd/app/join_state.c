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

#include <unistd.h>

#include "common/ws/eapol_relay.h"

#include "wsrd.h"
#include "ws.h"

#include "join_state.h"

void join_state_1_enter(struct wsrd *wsrd)
{
    // Entering join state 1 means we probably want a fresh start
    wsrd->ws.pan_id = 0xffff;
    memset(&wsrd->ws.jm, 0, sizeof(wsrd->ws.jm));
    supp_reset(&wsrd->supp);
    wsrd->eapol_target_eui64 = ieee802154_addr_bc;
    wsrd->ws.pan_version = -1;
    ipv6_neigh_clean(&wsrd->ipv6);
    ws_neigh_clean(&wsrd->ws.neigh_table);
    INFO("Join state 1: Select PAN");
    trickle_start(&wsrd->pas_tkl);
    timer_start_rel(NULL, &wsrd->pan_selection_timer, wsrd->config.disc_cfg.Imin_ms);
}

static void join_state_1_exit(struct wsrd *wsrd)
{
    BUG_ON(timer_stopped(&wsrd->pas_tkl.timer_interval));

    trickle_stop(&wsrd->pas_tkl);
}

/*
 * Join state 3: Reconnect
 * - PAN ID is known
 * - GTKs are known
 *
 * This state allows to reconnect to a previously known PAN while giving us
 * the opportunity to change PAN if any eligible is found.
 * This is why we start sending both PAS and PCS.
 */
static void join_state_3_reconnect_enter(struct wsrd *wsrd)
{
    // TODO: handle RX of PA from new PAN
    BUG_ON(wsrd->ws.pan_id == 0xffff);
    BUG_ON(!supp_get_gtkl(wsrd->supp.gtks, WS_GTK_COUNT));

    INFO("Join state 3: Reconnect");
    wsrd->ws.pan_version = -1;
    wsrd->pcs_nb = -1;

    trickle_start(&wsrd->pas_tkl);
    trickle_start(&wsrd->pcs_tkl);
}

static void join_state_3_reconnect_exit(struct wsrd *wsrd)
{
    trickle_stop(&wsrd->pas_tkl);
    trickle_stop(&wsrd->pcs_tkl);
}

static void join_state_2_enter(struct wsrd *wsrd)
{
    BUG_ON(wsrd->ws.pan_id == 0xffff);

    INFO("Join state 2: Authenticate");
    supp_start_key_request(&wsrd->supp);
}

static void join_state_3_enter(struct wsrd *wsrd)
{
    BUG_ON(wsrd->ws.pan_id == 0xffff);
    BUG_ON(!supp_get_gtkl(wsrd->supp.gtks, WS_GTK_COUNT));

    wsrd->ws.pan_version = -1;
    wsrd->pcs_nb  = 0;

    INFO("Join state 3: Acquire PAN Config");
    trickle_start(&wsrd->pcs_tkl);
}

static void join_state_3_exit(struct wsrd *wsrd)
{
    BUG_ON(timer_stopped(&wsrd->pcs_tkl.timer_interval));

    trickle_stop(&wsrd->pcs_tkl);
}

static void join_state_4_choose_parent_enter(struct wsrd *wsrd)
{
    struct ws_neigh *neigh;

    BUG_ON(wsrd->ws.pan_id == 0xffff);
    BUG_ON(!supp_get_gtkl(wsrd->supp.gtks, WS_GTK_COUNT));
    BUG_ON(wsrd->ws.pan_version < 0);

    INFO("Join state 4: Configure Routing - Choose Parent");
    /*
     * Before getting passed join state 3, the broadcast schedule is not configured,
     * which means that we may have sent unicast frames on a broadcast slot.
     * This would results in retries and therefore increase ETX of neighbors.
     * We reset the ETX of all neighbors to avoid this side effect during
     * parent selection.
     */
    SLIST_FOREACH(neigh, &wsrd->ws.neigh_table.neigh_list, link)
        ws_neigh_etx_reset(&wsrd->ws.neigh_table, neigh);
    rpl_start_dis(&wsrd->ipv6);
}

static void join_state_4_choose_parent_exit(struct wsrd *wsrd)
{
    BUG_ON(rfc8415_txalg_stopped(&wsrd->ipv6.rpl.dis_txalg));

    rfc8415_txalg_stop(&wsrd->ipv6.rpl.dis_txalg);
}

static void join_state_4_routing_enter(struct wsrd *wsrd)
{
    struct ipv6_neigh *parent = rpl_neigh_pref_parent(&wsrd->ipv6);

    BUG_ON(wsrd->ws.pan_id == 0xffff);
    BUG_ON(!supp_get_gtkl(wsrd->supp.gtks, WS_GTK_COUNT));
    BUG_ON(wsrd->ws.pan_version < 0);
    BUG_ON(!parent);

    INFO("Join state 4: Configure Routing - DHCP/NS(ARO)/DAO");
    if (!wsrd->ipv6.dhcp.running) {
        dhcp_client_start(&wsrd->ipv6.dhcp);
        return;
    }
    // We are trying to renew our address
    if (!rfc8415_txalg_stopped(&wsrd->ipv6.dhcp.solicit_txalg)) {
        rfc8415_txalg_start(&wsrd->ipv6.dhcp.solicit_txalg);
        return;
    }
    // Send NS(ARO) to register our address
    ipv6_nud_set_state(&wsrd->ipv6, parent, IPV6_NUD_PROBE);
}

static void join_state_5_enter(struct wsrd *wsrd)
{
    const struct ipv6_neigh *parent = rpl_neigh_pref_parent(&wsrd->ipv6);

    BUG_ON(wsrd->ws.pan_id == 0xffff);
    BUG_ON(!supp_get_gtkl(wsrd->supp.gtks, WS_GTK_COUNT));
    BUG_ON(wsrd->ws.pan_version < 0);
    BUG_ON(!parent);
    BUG_ON(!wsrd->ipv6.dhcp.running);
    BUG_ON(IN6_IS_ADDR_UNSPECIFIED(&wsrd->ipv6.dhcp.iaaddr.ipv6));
    // TODO: make sure NS(ARO) refresh timer is running
    BUG_ON(!parent->rpl->dao_ack_received);
    // TODO: make sure DAO refresh timer is running

    INFO("Join state 5: Operational");
    // TODO: enable when full parenting ready
    // rpl_start_dio(&wsrd->ipv6);
    close(wsrd->ws.eapol_relay_fd);
    wsrd->ws.eapol_relay_fd = eapol_relay_start(wsrd->ipv6.tun.ifname);
}

static void join_state_5_exit(struct wsrd *wsrd)
{
    BUG_ON(wsrd->ws.eapol_relay_fd < 0);

    // TODO: inform the network that we are leaving
    close(wsrd->ws.eapol_relay_fd);
    wsrd->ws.eapol_relay_fd = -1;
    // TODO: stop DIO, PA, PC
}

static const struct wsrd_state_transition state_discovery_transitions[] = {
    { WSRD_EVENT_PA_FROM_NEW_PAN, WSRD_STATE_AUTHENTICATE },
    { },
};

static const struct wsrd_state_transition state_reconnect_transitions[] = {
    { WSRD_EVENT_PC_RX,            WSRD_STATE_RPL_PARENT },
    { WSRD_EVENT_PA_FROM_PREV_PAN, WSRD_STATE_CONFIGURE },
    { WSRD_EVENT_PA_FROM_NEW_PAN,  WSRD_STATE_AUTHENTICATE },
    { WSRD_EVENT_AUTH_FAIL,        WSRD_STATE_DISCOVERY },
    { },
};

static const struct wsrd_state_transition state_authenticate_transitions[] = {
    { WSRD_EVENT_AUTH_SUCCESS,    WSRD_STATE_CONFIGURE },
    { WSRD_EVENT_AUTH_FAIL,       WSRD_STATE_DISCOVERY },
    { WSRD_EVENT_PA_FROM_NEW_PAN, WSRD_STATE_AUTHENTICATE },
    { },
};

static const struct wsrd_state_transition state_configure_transitions[] = {
    { WSRD_EVENT_PC_RX,           WSRD_STATE_RPL_PARENT },
    { WSRD_EVENT_PC_TIMEOUT,      WSRD_STATE_RECONNECT },
    { WSRD_EVENT_PA_FROM_NEW_PAN, WSRD_STATE_AUTHENTICATE },
    { WSRD_EVENT_AUTH_FAIL,       WSRD_STATE_DISCOVERY },
    { },
};

static const struct wsrd_state_transition state_rpl_parent_transitions[] = {
    { WSRD_EVENT_RPL_NEW_PREF_PARENT, WSRD_STATE_ROUTING },
    { WSRD_EVENT_PAN_TIMEOUT,         WSRD_STATE_RECONNECT },
    { WSRD_EVENT_RPL_NO_CANDIDATE,    WSRD_STATE_RECONNECT },
    { WSRD_EVENT_PA_FROM_NEW_PAN,     WSRD_STATE_AUTHENTICATE },
    { WSRD_EVENT_AUTH_FAIL,           WSRD_STATE_DISCOVERY },
    { },
};

static const struct wsrd_state_transition state_routing_transitions[] = {
    { WSRD_EVENT_ROUTING_SUCCESS,  WSRD_STATE_OPERATIONAL },
    { WSRD_EVENT_PAN_TIMEOUT,      WSRD_STATE_RECONNECT },
    { WSRD_EVENT_RPL_NO_CANDIDATE, WSRD_STATE_RECONNECT },
    { WSRD_EVENT_PA_FROM_NEW_PAN,  WSRD_STATE_AUTHENTICATE },
    { WSRD_EVENT_AUTH_FAIL,        WSRD_STATE_DISCOVERY },
    { },
};

static const struct wsrd_state_transition state_operational_transitions[] = {
    { WSRD_EVENT_PAN_TIMEOUT,      WSRD_STATE_RECONNECT },
    { WSRD_EVENT_RPL_NO_CANDIDATE, WSRD_STATE_RECONNECT },
    { WSRD_EVENT_PA_FROM_NEW_PAN,  WSRD_STATE_AUTHENTICATE },
    { WSRD_EVENT_AUTH_FAIL,        WSRD_STATE_DISCOVERY },
    { },
};

static const struct wsrd_state_entry join_states[] = {
    [WSRD_STATE_DISCOVERY] = {
        .state = WSRD_STATE_DISCOVERY,
        .enter = join_state_1_enter,
        .exit  = join_state_1_exit,
        .transitions = state_discovery_transitions,
    },
    [WSRD_STATE_RECONNECT] = {
        .state = WSRD_STATE_RECONNECT,
        .enter = join_state_3_reconnect_enter,
        .exit  = join_state_3_reconnect_exit,
        .transitions = state_reconnect_transitions,
    },
    [WSRD_STATE_AUTHENTICATE] = {
        .state = WSRD_STATE_AUTHENTICATE,
        .enter = join_state_2_enter,
        .exit  = NULL,
        .transitions = state_authenticate_transitions,
    },
    [WSRD_STATE_CONFIGURE] = {
        .state = WSRD_STATE_CONFIGURE,
        .enter = join_state_3_enter,
        .exit  = join_state_3_exit,
        .transitions = state_configure_transitions,
    },
    [WSRD_STATE_RPL_PARENT] = {
        .state = WSRD_STATE_RPL_PARENT,
        .enter = join_state_4_choose_parent_enter,
        .exit  = join_state_4_choose_parent_exit,
        .transitions = state_rpl_parent_transitions,
    },
    [WSRD_STATE_ROUTING] = {
        .state = WSRD_STATE_ROUTING,
        .enter = join_state_4_routing_enter,
        .exit  = NULL,
        .transitions = state_routing_transitions,
    },
    [WSRD_STATE_OPERATIONAL] = {
        .state = WSRD_STATE_OPERATIONAL,
        .enter = join_state_5_enter,
        .exit  = join_state_5_exit,
        .transitions = state_operational_transitions,
    },
};

void join_state_transition(struct wsrd *wsrd, enum wsrd_event event)
{
    const struct wsrd_state_entry *state = &join_states[wsrd->state];

    for (const struct wsrd_state_transition *transition = state->transitions; transition->event; transition++) {
        if (transition->event != event)
            continue;
        if (state->exit)
            state->exit(wsrd);

        wsrd->state = transition->next_state;
        state = &join_states[wsrd->state];

        if (state->enter)
            state->enter(wsrd);
        break;
    }
}
