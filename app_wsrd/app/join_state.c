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
#include "common/ipv6/ipv6_addr.h"
#include "common/dhcp_client.h"
#include "common/dbus.h"

#include "app_wsrd/supplicant/supplicant_storage.h"
#include "wsrd_storage.h"
#include "wsrd.h"
#include "ws.h"

#include "join_state.h"

void join_state_1_enter(struct wsrd *wsrd)
{
    // Entering join state 1 means we probably want a fresh start
    wsrd_storage_clear();
    ws_set_pan_id(wsrd, 0xffff);
    wsrd->prev_pan_id = 0xffff;
    memset(&wsrd->ws.jm, 0, sizeof(wsrd->ws.jm));
    wsrd->ws.has_jm = false;
    supp_reset(&wsrd->supp);
    supp_storage_clear();
    wsrd->eapol_target_eui64 = EUI64_BC;
    wsrd->ws.gak_index = 0;
    ws_set_pan_version(wsrd, -1);
    dhcp_client_stop(&wsrd->ipv6.dhcp);
    rpl_stop(&wsrd->ipv6);
    timer_stop(NULL, &wsrd->pan_timeout_timer);
    ipv6_neigh_clean(&wsrd->ipv6);
    ws_neigh_clean(&wsrd->ws.neigh_table);
    wsrd->ws.neigh_table.ws_etx_ctx.update_min_tx_req_cnt = WS_ETX_UPDATE_MIN_TX_REQ_CNT;
    wsrd->ws.neigh_table.ws_etx_ctx.update_min_delay_ms = WS_ETX_UPDATE_MIN_DELAY_MS;
    wsrd->ws.neigh_table.ws_etx_ctx.refresh_period_ms = WS_ETX_REFRESH_PERIOD_MS;
    INFO("Join state 1: Select PAN");
    trickle_start(&wsrd->pas_tkl);
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
void join_state_3_reconnect_enter(struct wsrd *wsrd)
{
    BUG_ON(wsrd->ws.pan_id == 0xffff);
    BUG_ON(!supp_get_gtkl(wsrd->supp.gtks, WS_GTK_COUNT));

    INFO("Join state 3: Reconnect");
    /*
     * - sets prev_pan_id for PCS TX/PA from prev PAN RX
     * - sets pan_id to 0xffff for PA RX from new PAN
     */
    ws_set_pan_id(wsrd, 0xffff);
    wsrd->eapol_target_eui64 = EUI64_BC;
    rfc8415_txalg_stop(&wsrd->supp.key_request_txalg);
    wsrd->ws.gak_index = 0;
    ws_set_pan_version(wsrd, -1);
    wsrd->pcs_nb = 0;
    dhcp_client_stop(&wsrd->ipv6.dhcp);
    ipv6_neigh_clean(&wsrd->ipv6);
    rpl_stop(&wsrd->ipv6);
    timer_stop(NULL, &wsrd->pan_timeout_timer);
    wsrd->ws.neigh_table.ws_etx_ctx.update_min_tx_req_cnt = WS_ETX_UPDATE_MIN_TX_REQ_CNT;
    wsrd->ws.neigh_table.ws_etx_ctx.update_min_delay_ms = WS_ETX_UPDATE_MIN_DELAY_MS;
    wsrd->ws.neigh_table.ws_etx_ctx.refresh_period_ms = WS_ETX_REFRESH_PERIOD_MS;

    trickle_start(&wsrd->pas_tkl);
    trickle_start(&wsrd->pcs_tkl);
    ws_if_send_pas(&wsrd->ws);
    ws_if_send_pcs(&wsrd->ws, wsrd->prev_pan_id);
}

static void join_state_3_reconnect_exit(struct wsrd *wsrd)
{
    trickle_stop(&wsrd->pas_tkl);
    trickle_stop(&wsrd->pcs_tkl);
}

static void join_state_2_enter(struct wsrd *wsrd)
{
    BUG_ON(wsrd->ws.pan_id == 0xffff);

    /*
     * Reset is needed to ensure we do not send invalid (L)GTKL when
     * transitionning to a new PAN.
     */
    supp_reset(&wsrd->supp);

    INFO("Join state 2: Authenticate");
    supp_start_key_request(&wsrd->supp);
}

static void join_state_3_enter(struct wsrd *wsrd)
{
    BUG_ON(wsrd->ws.pan_id == 0xffff);
    BUG_ON(!supp_get_gtkl(wsrd->supp.gtks, WS_GTK_COUNT));

    ws_set_pan_version(wsrd, -1);
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
    BUG_ON(timer_stopped(&wsrd->pan_timeout_timer));

    INFO("Join state 4: Configure Routing - Choose Parent");
    /*
     * Before getting passed join state 3, the broadcast schedule is not configured,
     * which means that we may have sent unicast frames on a broadcast slot.
     * This would results in retries and therefore increase ETX of neighbors.
     * We reset the ETX of all neighbors to avoid this side effect during
     * parent selection.
     * To allow faster ETX computation during the initial connection, we lower
     * some of the ETX parameters. See IPV6_NUD_DELAY state for more details.
     */
    dhcp_client_stop(&wsrd->ipv6.dhcp);
    if (wsrd->last_event == WSRD_EVENT_PC_RX) {
        SLIST_FOREACH(neigh, &wsrd->ws.neigh_table.neigh_list, link)
            ws_etx_reset(&wsrd->ws.neigh_table.ws_etx_ctx, &neigh->ws_etx);
        wsrd->ws.neigh_table.ws_etx_ctx.update_min_tx_req_cnt = 1;
        wsrd->ws.neigh_table.ws_etx_ctx.update_min_delay_ms = 0;
        wsrd->ws.neigh_table.ws_etx_ctx.refresh_period_ms = 0;
    }
    rpl_start(&wsrd->ipv6);
    rpl_start_dis(&wsrd->ipv6);
}

static void join_state_4_choose_parent_exit(struct wsrd *wsrd)
{
    BUG_ON(rfc8415_txalg_stopped(&wsrd->ipv6.rpl.dis_txalg));

    rfc8415_txalg_stop(&wsrd->ipv6.rpl.dis_txalg);
    wsrd->ws.neigh_table.ws_etx_ctx.update_min_tx_req_cnt = WS_ETX_UPDATE_MIN_TX_REQ_CNT;
    wsrd->ws.neigh_table.ws_etx_ctx.update_min_delay_ms = WS_ETX_UPDATE_MIN_DELAY_MS;
    wsrd->ws.neigh_table.ws_etx_ctx.refresh_period_ms = WS_ETX_REFRESH_PERIOD_MS;
}

static void join_state_4_routing_enter(struct wsrd *wsrd)
{
    struct ipv6_neigh *parent = rpl_neigh_pref_parent(&wsrd->ipv6);

    BUG_ON(wsrd->ws.pan_id == 0xffff);
    BUG_ON(!supp_get_gtkl(wsrd->supp.gtks, WS_GTK_COUNT));
    BUG_ON(wsrd->ws.pan_version < 0);
    BUG_ON(!parent);
    BUG_ON(wsrd->ipv6.dhcp.running);

    INFO("Join state 4: Configure Routing - DHCP/NS(ARO)/DAO");
    dhcp_client_start(&wsrd->ipv6.dhcp);
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
    BUG_ON(timer_stopped(&parent->own_aro_timer));
    BUG_ON(!parent->rpl->dao_ack_received);
    BUG_ON(timer_stopped(&wsrd->ipv6.rpl.dao_refresh_timer));
    BUG_ON(wsrd->ws.eapol_relay_fd >= 0);

    INFO("Join state 5: Operational");
    rpl_start_dio(&wsrd->ipv6);
    wsrd->ws.eapol_relay_fd = eapol_relay_start(wsrd->ipv6.tun.ifname);
    trickle_start(&wsrd->pa_tkl);
    trickle_start(&wsrd->pc_tkl);
    wsrd->dhcp_relay.server_addr = parent->rpl->dio.dodag_id;
    wsrd->dhcp_relay.link_addr   = wsrd->ipv6.dhcp.iaaddr.ipv6;
    dhcp_relay_start(&wsrd->dhcp_relay);
}

static void join_state_5_exit(struct wsrd *wsrd)
{
    BUG_ON(wsrd->ws.eapol_relay_fd < 0);

    /*
     * Do not stop RPL or PAN timeout here: timer states are used when
     * entering the disconnecting state.
     */
    close(wsrd->ws.eapol_relay_fd);
    wsrd->ws.eapol_relay_fd = -1;
    dhcp_relay_stop(&wsrd->dhcp_relay);
    trickle_stop(&wsrd->pa_tkl);
    trickle_stop(&wsrd->pc_tkl);
}

static void join_state_disconnecting_enter(struct wsrd *wsrd)
{
    struct ipv6_neigh *parent = rpl_neigh_pref_parent(&wsrd->ipv6);

    rfc8415_txalg_stop(&wsrd->supp.key_request_txalg);
    // NOTE: do not stop the DHCP client here since we may need our GUA
    rfc8415_txalg_stop(&wsrd->ipv6.dhcp.solicit_txalg);
    /*
     * NOTES:
     * - This timer is necessary to ensure we do not transition too early
     *   in discovery/reconnect state. More precisely, entering those states
     *   resets the active GAK index, making any secured frame TX impossible.
     * - We start the timer even if we have no parent considering RPL took
     *   care of unregistration in that case.
     * - 2s is an arbitrary waiting time to ensure all unregistration packets
     *   were TX to the RCP.
     */
    timer_start_rel(NULL, &wsrd->unregistration_timer, 2 * 1000);

    /*
     * - If disconnecting on WSRD_EVENT_RPL_NO_CANDIDATE, RPL already took care
     *   of NS(ARO) lifetime 0, poisoning, and deleting our parent. Nothing to
     *   do here.
     * - On WSRD_EVENT_RPL_PREF_LOST we are going back to JS 4, so we do not
     *   stop the PAN timeout timer to ensure PAN loss and parent selection
     *   timeout detection.
     * - If we have a parent, wsrd is stopping or a PAN timeout occurred. A PAN
     *   timeout can happen in any JS >= 4.
     */
    if (!parent || IN6_IS_ADDR_UNSPECIFIED(&wsrd->ipv6.dhcp.iaaddr.ipv6)) {
        if (wsrd->last_event != WSRD_EVENT_RPL_PREF_LOST)
            timer_stop(NULL, &wsrd->pan_timeout_timer);
        // Stopping RPL to prevent any parent selection
        rpl_stop(&wsrd->ipv6);
        return;
    }

    /*
     * - On PAN timeout, the BR seems unreachable, we can skip DAO No-Path.
     * - If called before JS 5 and no DAO was sent, we can skip DAO No-Path.
     */
    if (!timer_stopped(&wsrd->pan_timeout_timer) && !timer_stopped(&wsrd->ipv6.rpl.dao_refresh_timer))
        rpl_send_dao_no_path(&wsrd->ipv6);
    timer_stop(NULL, &wsrd->pan_timeout_timer);
    // Poisoning: clearing the flag will set the DIO's rank to 0xffff
    parent->rpl->is_parent = false;
    // Skip poisoning if called before JS 5
    if (!trickle_stopped(&wsrd->ipv6.rpl.dio_trickle))
        rpl_send_dio(&wsrd->ipv6, parent, &ipv6_addr_all_rpl_nodes_link);
    /*
     * Always send NS(ARO) lifetime 0 in case NS(ARO) ACK was not received
     * before changing parent.
     */
    timer_stop(&wsrd->ipv6.timer_group, &parent->own_aro_timer);
    ipv6_send_ns_aro(&wsrd->ipv6, parent, 0);
    rpl_stop(&wsrd->ipv6);
}

static inline void join_state_disconnecting_exit(struct wsrd *wsrd)
{
    // Will make the main loop stop and exit the program cleanly.
    if (wsrd->last_event == WSRD_EVENT_DISCONNECT)
        wsrd->running = false;
}

static const struct wsrd_state_transition state_discovery_transitions[] = {
    { WSRD_EVENT_PA_FROM_NEW_PAN, WSRD_STATE_AUTHENTICATE },
    { WSRD_EVENT_DISCONNECT,      WSRD_STATE_DISCONNECTING },
    { },
};

static const struct wsrd_state_transition state_reconnect_transitions[] = {
    { WSRD_EVENT_PC_RX,            WSRD_STATE_RPL_PARENT },
    { WSRD_EVENT_PC_TIMEOUT,       WSRD_STATE_DISCOVERY },
    { WSRD_EVENT_PA_FROM_PREV_PAN, WSRD_STATE_CONFIGURE },
    { WSRD_EVENT_PA_FROM_NEW_PAN,  WSRD_STATE_AUTHENTICATE },
    { WSRD_EVENT_AUTH_FAIL,        WSRD_STATE_DISCOVERY },
    { WSRD_EVENT_DISCONNECT,       WSRD_STATE_DISCONNECTING },
    { },
};

static const struct wsrd_state_transition state_authenticate_transitions[] = {
    { WSRD_EVENT_AUTH_SUCCESS,    WSRD_STATE_CONFIGURE },
    { WSRD_EVENT_AUTH_FAIL,       WSRD_STATE_DISCOVERY },
    { WSRD_EVENT_PA_FROM_NEW_PAN, WSRD_STATE_AUTHENTICATE },
    { WSRD_EVENT_DISCONNECT,      WSRD_STATE_DISCONNECTING },
    { },
};

static const struct wsrd_state_transition state_configure_transitions[] = {
    { WSRD_EVENT_PC_RX,           WSRD_STATE_RPL_PARENT },
    { WSRD_EVENT_PC_TIMEOUT,      WSRD_STATE_RECONNECT },
    { WSRD_EVENT_AUTH_FAIL,       WSRD_STATE_DISCOVERY },
    { WSRD_EVENT_DISCONNECT,      WSRD_STATE_DISCONNECTING },
    { },
};

static const struct wsrd_state_transition state_rpl_parent_transitions[] = {
    { WSRD_EVENT_RPL_NEW_PREF_PARENT, WSRD_STATE_ROUTING },
    { WSRD_EVENT_PAN_TIMEOUT,         WSRD_STATE_RECONNECT },
    { WSRD_EVENT_AUTH_FAIL,           WSRD_STATE_DISCOVERY },
    { WSRD_EVENT_DISCONNECT,          WSRD_STATE_DISCONNECTING },
    { },
};

static const struct wsrd_state_transition state_routing_transitions[] = {
    { WSRD_EVENT_ROUTING_SUCCESS,  WSRD_STATE_OPERATIONAL },
    { WSRD_EVENT_PAN_TIMEOUT,      WSRD_STATE_DISCONNECTING },
    { WSRD_EVENT_RPL_PREF_LOST,    WSRD_STATE_DISCONNECTING },
    { WSRD_EVENT_RPL_NO_CANDIDATE, WSRD_STATE_DISCONNECTING },
    { WSRD_EVENT_AUTH_FAIL,        WSRD_STATE_DISCONNECTING },
    { WSRD_EVENT_DISCONNECT,       WSRD_STATE_DISCONNECTING },
    { },
};

static const struct wsrd_state_transition state_operational_transitions[] = {
    { WSRD_EVENT_PAN_TIMEOUT,      WSRD_STATE_DISCONNECTING },
    { WSRD_EVENT_RPL_PREF_LOST,    WSRD_STATE_DISCONNECTING },
    { WSRD_EVENT_RPL_NO_CANDIDATE, WSRD_STATE_DISCONNECTING },
    { WSRD_EVENT_AUTH_FAIL,        WSRD_STATE_DISCONNECTING },
    { WSRD_EVENT_DISCONNECT,       WSRD_STATE_DISCONNECTING },
    { },
};

static const struct wsrd_state_transition state_disconnecting_transitions[] = {
    { WSRD_EVENT_PAN_TIMEOUT,      WSRD_STATE_RECONNECT },
    { WSRD_EVENT_RPL_PREF_LOST,    WSRD_STATE_RPL_PARENT },
    { WSRD_EVENT_RPL_NO_CANDIDATE, WSRD_STATE_RECONNECT },
    { WSRD_EVENT_AUTH_FAIL,        WSRD_STATE_DISCOVERY },
    // Needed to trigger join_state_disconnecting_exit()
    { WSRD_EVENT_DISCONNECT,       WSRD_STATE_DISCONNECTING },
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
    [WSRD_STATE_DISCONNECTING] = {
        .state = WSRD_STATE_DISCONNECTING,
        .enter = join_state_disconnecting_enter,
        .exit  = join_state_disconnecting_exit,
        .transitions = state_disconnecting_transitions,
    },
};

void join_state_transition(struct wsrd *wsrd, enum wsrd_event event)
{
    const struct wsrd_state_entry *state = &join_states[wsrd->state];

    for (const struct wsrd_state_transition *transition = state->transitions; transition->event; transition++) {
        if (transition->event != event)
            continue;

        wsrd->last_event = event;

        if (state->exit)
            state->exit(wsrd);

        wsrd->state = transition->next_state;
        state = &join_states[wsrd->state];

        if (state->enter)
            state->enter(wsrd);
        dbus_emit_change("JoinState");
        break;
    }
}
