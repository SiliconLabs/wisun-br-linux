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
#include <errno.h>
#include <math.h>

#include "common/specs/ieee802154.h"
#include "common/specs/ieee802159.h"
#include "common/ws/eapol_relay.h"
#include "common/ws/ws_ie.h"
#include "common/ws/ws_ie_validation.h"
#include "common/ws/ws_interface.h"
#include "common/ws/ws_regdb.h"
#include "common/ws/ws_types.h"
#include "common/ipv6/ipv6_addr.h"
#include "common/hif.h"
#include "common/ieee802154_ie.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/memutils.h"
#include "common/mpx.h"
#include "common/named_values.h"
#include "common/dbus.h"
#include "common/string_extra.h"
#include "common/sys_queue_extra.h"
#include "common/time_extra.h"
#include "common/seqno.h"
#include "common/rail_config.h"
#include "common/version.h"
#include "common/rand.h"
#include "app_wsrd/ipv6/6lowpan.h"
#include "app_wsrd/app/wsrd_storage.h"
#include "app_wsrd/app/join_state.h"
#include "app_wsrd/app/wsrd.h"

#include "ws.h"

#ifndef EAPOL_TARGET_AUTO_SELECT_DBM
#define EAPOL_TARGET_AUTO_SELECT_DBM -60
#endif

/*
 * Maximum number of candidates to send unicast DIS.
 * If we have more than this number of candidates, a multicast DIS is also sent.
 * If we have no candidates, we send a multicast DIS.
 */
#define WS_RPL_DIS_UC_CAND_MAX 5

/*
 *   Wi-SUN FAN1.1v09 6.3.2.3.2.3 PAN Information Element (PAN-IE)
 * The Routing Cost field is a 16 bit unsigned integer which MUST be set to an
 * estimate of the transmitting node’s routing path ETX to the Border Router.
 * This value is calculated as the transmitting node’s ETX to its routing parent
 * added to the Routing Cost reported by that parent [...].
 */
static uint16_t ws_get_own_routing_cost(struct wsrd *wsrd)
{
    const struct ipv6_neigh *ipv6_parent = rpl_neigh_get_parent(&wsrd->ipv6, RPL_PATH_CTL_PREFERRED);
    const struct ws_neigh *ws_parent;

    if (!ipv6_parent)
        return 0xffff;
    ws_parent = ws_neigh_get(&wsrd->ws.neigh_table, &ipv6_parent->eui64);
    BUG_ON(!ws_parent);

    // Note: overflow during float to int conversion is undefined behavior
    if (ws_parent->ie_pan.routing_cost + (uint16_t)ws_parent->ws_etx.etx > 0xffff)
        return 0xffff;
    return ws_parent->ie_pan.routing_cost + (uint16_t)ws_parent->ws_etx.etx;
}

void ws_sync_fhss_bc(struct wsrd *wsrd, const struct ws_neigh *ws_neigh)
{
    struct ws_neigh *parent = ws_neigh_get(&wsrd->ws.neigh_table, &wsrd->eapol_target_eui64);

    /*
     * If we receive a PC with an updated PAN version from a neighbor that is
     * not our parent, we still update our BS information and indicate the RCP
     * to follow our parent's timings, if we have one.
     * This avoids having to synchronize again on RX of a PC from our parent.
     */
    rcp_set_fhss_ffn_bc(&wsrd->ws.rcp,
                        ws_neigh->fhss.ffn.bc_interval_ms,
                        ws_neigh->fhss.ffn.bsi,
                        ws_neigh->fhss.ffn.bc_dwell_interval_ms,
                        ws_neigh->fhss.bc_channel_list,
                        ws_neigh->fhss.ffn.bt_rx_tstamp_us,
                        ws_neigh->fhss.ffn.bc_slot_number,
                        ws_neigh->fhss.ffn.bc_interval_offset_ms,
                        parent ? parent->eui64.u8 : ws_neigh->eui64.u8,
                        parent ? parent->frame_counter_min : ws_neigh->frame_counter_min);
    wsrd->fhss_bc_synced_to_target = parent != NULL;
    wsrd->ws.fhss.bc_interval = ws_neigh->fhss.ffn.bc_interval_ms;
    wsrd->ws.fhss.bc_dwell_interval = ws_neigh->fhss.ffn.bc_dwell_interval_ms;
    wsrd->ws.fhss.bsi = ws_neigh->fhss.ffn.bsi;
    memcpy(wsrd->ws.fhss.bc_chan_mask, ws_neigh->fhss.bc_channel_list, sizeof(wsrd->ws.fhss.bc_chan_mask));
}

void ws_set_pan_id(struct wsrd *wsrd, uint16_t pan_id)
{
    if (wsrd->ws.pan_id == pan_id)
        return;
    wsrd->ws.pan_id = pan_id;
    rcp_set_filter_pan_id(&wsrd->ws.rcp, pan_id);
    dbus_emit_change("PanId");
}

static bool ws_is_eapol_target_valid(struct wsrd *wsrd, struct ws_neigh *candidate, uint16_t pan_id,
                                     int rsl_in_threshold_dbm)
{
    if (pan_id != 0xffff && candidate->pan_id != pan_id)
        return false;
    if (!candidate->last_pa_rx_time_s)
        return false;
    if (candidate->ie_pan.routing_cost == 0xffff)
        return false;
    if (candidate->rsl_in_dbm_unsecured < rsl_in_threshold_dbm)
        return false;
    return true;
}

static void ws_on_eapol_target_selected(struct wsrd *wsrd, struct ws_neigh *selected_candidate)
{
    struct ws_neigh *tmp;

    memcpy(&wsrd->eapol_target_eui64, selected_candidate->eui64.u8, sizeof(selected_candidate->eui64.u8));
    ws_set_pan_id(wsrd, selected_candidate->pan_id);
    wsrd->fhss_bc_synced_to_target = false;

    if (selected_candidate->plf != 0xff)
        TRACE(TR_SECURITY, "eapol target candidate %-7s %s panid:0x%04x pan_cost:%u plf:%u%%", "select",
              tr_eui64(selected_candidate->eui64.u8), selected_candidate->pan_id,
              ws_neigh_get_pan_cost(selected_candidate), selected_candidate->plf);
    else
        TRACE(TR_SECURITY, "eapol target candidate %-7s %s panid:0x%04x pan_cost:%u plf:n/a", "select",
              tr_eui64(selected_candidate->eui64.u8), selected_candidate->pan_id,
              ws_neigh_get_pan_cost(selected_candidate));

    SLIST_FOREACH(tmp, &wsrd->ws.neigh_table.neigh_list, link)
        tmp->last_pa_rx_time_s = 0;

    if (wsrd->prev_pan_id != 0xffff && wsrd->prev_pan_id == wsrd->ws.pan_id)
        join_state_transition(wsrd, WSRD_EVENT_PA_FROM_PREV_PAN);
    else
        join_state_transition(wsrd, WSRD_EVENT_PA_FROM_NEW_PAN);
}

void ws_on_pan_selection_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct wsrd *wsrd = container_of(timer, struct wsrd, pan_selection_timer);
    const struct rcp_rail_config *rail_config = &wsrd->ws.rcp.rail_config_list[wsrd->ws.phy.rcp_rail_config_index];
    struct ws_neigh *selected_candidate = NULL;
    struct ws_neigh *candidate = NULL;
    uint16_t selected_pan_id;

    BUG_ON(!rail_config);

    /*
     *   Wi-SUN FAN 1.1v08, 6.3.2.3.2.12.1 PAN Load Factor Join Metric
     * This metric MAY be used in conjunction with a candidate neighbor’s
     * Routing Cost to determine a preferred PAN, overriding the PAN Cost
     * defined in sections 6.3.4.6.3.2.1 and 6.3.4.6.4.2.1.3.
     * It is RECOMMENDED that a receiving node choose the PAN with the lowest
     * PAN Load Factor, and if possible, avoid joining a PAN with a PAN Load
     * Factor of 90% or higher.
     */
    SLIST_FOREACH(candidate, &wsrd->ws.neigh_table.neigh_list, link) {
        /*
         *   Wi-SUN FAN 1.1v09 6.3.2.3.2.3 PAN Information Element (PAN-IE)
         * A node unable to act as an EAPOL target MAY set this field to the
         * maximum value of 0xFFFF.
         */
        if (!ws_is_eapol_target_valid(wsrd, candidate, 0xffff, rail_config->sensitivity_dbm))
            continue;
        if (!selected_candidate)
            selected_candidate = candidate;
        if (candidate->plf != 0xff && candidate->plf < selected_candidate->plf)
            selected_candidate = candidate;
        else if (ws_neigh_get_pan_cost(candidate) < ws_neigh_get_pan_cost(selected_candidate))
            selected_candidate = candidate;
    }
    if (!selected_candidate) {
        // NOTE: Change channel in case a bad one was picked previously.
        if (!version_older_than(wsrd->ws.rcp.version_api, 2, 14, 0))
            ws_fhss_uc_use_rand_fixed_chan(wsrd);
        return;
    }
    selected_pan_id = selected_candidate->pan_id;

    // Ensure we select the candidate with the lowest pan cost
    SLIST_FOREACH(candidate, &wsrd->ws.neigh_table.neigh_list, link) {
        if (!ws_is_eapol_target_valid(wsrd, candidate, selected_pan_id, rail_config->sensitivity_dbm))
            continue;
        if (ws_neigh_get_pan_cost(candidate) < ws_neigh_get_pan_cost(selected_candidate))
            selected_candidate = candidate;
    }
    ws_on_eapol_target_selected(wsrd, selected_candidate);
}

/*
 *   Wi-SUN FAN 1.1v08, 6.3.4.6.3.2.1 FFN Join State 1: Select PAN
 * 1. The set of FFNs from which the joining FFN receives an acceptable PA
 * within DISC_IMIN of the end of the previous PAS interval.
 */
void ws_on_pas_interval_done(struct trickle *tkl, struct timer_group *group)
{
    struct wsrd *wsrd = container_of(tkl, struct wsrd, pas_tkl);

    timer_start_rel(NULL, &wsrd->pan_selection_timer, wsrd->pas_tkl.cfg->Imin_ms);
}

static void ws_eapol_target_add(struct wsrd *wsrd, struct ws_ind *ind, struct ws_pan_ie *ie_pan, struct ws_jm_ie *ie_jm)
{
    const struct ws_jm *jm = ws_wp_nested_jm_get_metric(ie_jm, WS_JM_PLF);
    uint32_t pan_cost = ws_neigh_get_pan_cost(ind->neigh);
    bool added = !ind->neigh->last_pa_rx_time_s;

    ind->neigh->pan_id   = ind->hdr.pan_id;
    ind->neigh->last_pa_rx_time_s = time_now_s(CLOCK_MONOTONIC);
    if (jm)
        ind->neigh->plf = jm->plf;
    else
        ind->neigh->plf = 0xff;

    if (ind->neigh->plf != 0xff)
        TRACE(TR_SECURITY, "eapol target candidate %-7s %s panid:0x%04x pan_cost:%u plf:%u%%",
              added ? "add" : "refresh", tr_eui64(ind->neigh->eui64.u8), ind->neigh->pan_id,
              pan_cost, ind->neigh->plf);
    else
        TRACE(TR_SECURITY, "eapol target candidate %-7s %s panid:0x%04x pan_cost:%u plf:n/a",
              added ? "add" : "refresh", tr_eui64(ind->neigh->eui64.u8), ind->neigh->pan_id, pan_cost);

    if (ws_is_eapol_target_valid(wsrd, ind->neigh, 0xffff, EAPOL_TARGET_AUTO_SELECT_DBM))
        ws_on_eapol_target_selected(wsrd, ind->neigh);
}

void ws_recv_pa(struct wsrd *wsrd, struct ws_ind *ind)
{
    uint16_t own_routing_cost = ws_get_own_routing_cost(wsrd);
    struct ws_jm_ie ie_jm = { };
    struct ws_pan_ie ie_pan;
    struct ws_us_ie ie_us;
    bool has_jm;

    if (ind->hdr.pan_id == 0xffff) {
        TRACE(TR_DROP, "drop %s: missing PAN ID", "15.4");
        return;
    }
    if (wsrd->ws.pan_id != 0xffff && wsrd->ws.pan_id != ind->hdr.pan_id) {
        TRACE(TR_DROP, "drop %s: PAN ID mismatch", "15.4");
        return;
    }
    if (!ws_ie_validate_netname(wsrd->ws.netname, &ind->ie_wp))
        return;
    if (!ws_ie_validate_pan(&ind->ie_wp, &ie_pan))
        return;
    if (!ws_ie_validate_us(&wsrd->ws.fhss, &ind->ie_wp, &ie_us))
        return;
    has_jm = ws_wp_nested_jm_read(ind->ie_wp.data, ind->ie_wp.data_size, &ie_jm);

    ws_neigh_us_update(&wsrd->ws.fhss, &ind->neigh->fhss,
                       &ie_us.chan_plan, ie_us.dwell_interval);

    // TODO: POM-IE

    /*
     *   Wi-SUN FAN 1.1v09, 6.3.4.6.3.1 Usage of Trickle Timers
     * The Advertisement Trickle timer controls transmission rate of the PAN
     * Advertisement frame.
     * [...]
     * A consistent transmission is defined as a PAN Advertisement received by
     * an FFN with PAN ID and NETNAME-IE / Network Name matching that of the
     * receiving FFN, and with a PAN-IE / Routing Cost the same or worse (equal
     * to or greater, but different from 0xFFFF) than that of the receiving FFN.
     */
    if (ie_pan.routing_cost != 0xffff && ie_pan.routing_cost >= own_routing_cost)
        trickle_consistent(&wsrd->pa_tkl);

    ind->neigh->ie_pan = ie_pan;

    if (wsrd->ws.pan_id == 0xffff)
        ws_eapol_target_add(wsrd, ind, &ie_pan, &ie_jm);
    if (!has_jm)
        return;
    /*
     *   Wi-SUN FAN 1.1v09, 6.3.2.3.5.1 Frames for FFN-FFN Messaging
     * The PAN Advertisement frame (PA):
     * [...]
     * If multiple JM-IEs are received from a single PAN with different Content
     * Versions, the JM-IE with the newest Content Version MUST be used for
     * processing and transmission.
     * [...]
     * If a Join Metric is not received in the latest JM-IE it MUST be removed
     * from the node’s list of join metrics and not forwarded in transmitted
     * JM-IEs.
     */
    if (!wsrd->ws.has_jm || seqno_cmp8(ie_jm.version, wsrd->ws.jm.version) > 0) {
        wsrd->ws.has_jm = true;
        wsrd->ws.jm = ie_jm;
    }
}

static void ws_recv_pas(struct wsrd *wsrd, struct ws_ind *ind)
{
    struct ws_us_ie ie_us;

    if (!ws_ie_validate_netname(wsrd->ws.netname, &ind->ie_wp))
        return;
    if (!ws_ie_validate_us(&wsrd->ws.fhss, &ind->ie_wp, &ie_us))
        return;

    ws_neigh_us_update(&wsrd->ws.fhss, &ind->neigh->fhss,
                       &ie_us.chan_plan, ie_us.dwell_interval);

    /*
     *   Wi-SUN FAN 1.1v09, 6.3.4.6.3.1 Usage of Trickle Timers
     * The Advertisement Solicit Trickle timer controls transmission rate of
     * the PAN Advertisement Solicit frame.
     * [...]
     * b. A consistent transmission is defined as a PAN Advertisement Solicit
     *    with NETNAME-IE / Network Name matching that configured on the FFN.
     * [...]
     * The Advertisement Trickle timer controls transmission rate of the PAN
     * Advertisement frame.
     * c. An inconsistent transmission is defined as a PAN Advertisement Solicit
     *    with NETNAME-IE matching that of the receiving FFN.
     */
    trickle_consistent(&wsrd->pas_tkl);
    trickle_inconsistent(&wsrd->pa_tkl, NULL);
}

void ws_on_pan_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct wsrd *wsrd = container_of(timer, struct wsrd, pan_timeout_timer);

    /*
     * NOTE: a PAN timeout is triggered a first time after 90% of pan_timeout_s
     * without hearing the BR. Having not heard the BR at this stage may be
     * normal if no traffic was initiated. If possible, we start a DAO sequence
     * to trigger a DAO-ACK from the BR and avoid disconnecting unecessarily.
     * A PAN timeout will really be triggered once we have reached
     * pan_timeout_s without hearing the BR.
     */
    if (!wsrd->pan_timeout_pending) {
        wsrd->pan_timeout_pending = true;
        /*
         * A PAN timeout can happen starting join state 4, meaning that we may
         * not even be able to send a DAO just yet.
         */
        if (!timer_stopped(&wsrd->ipv6.rpl.dao_refresh_timer))
            rpl_start_dao(&wsrd->ipv6);
        timer_start_rel(NULL, &wsrd->pan_timeout_timer,
                        (uint64_t)wsrd->config.pan_timeout_s * 100); // 10%
        return;
    }
    wsrd->pan_timeout_pending = false;
    INFO("PAN timeout");
    join_state_transition(wsrd, WSRD_EVENT_PAN_TIMEOUT);
}

void ws_pan_timeout_update(struct wsrd *wsrd)
{
    wsrd->pan_timeout_pending = false;
    timer_start_rel(NULL, &wsrd->pan_timeout_timer,
                    (uint64_t)wsrd->config.pan_timeout_s * 900); // 90%
}

static void ws_update_gak_index(struct wsrd *wsrd, uint8_t key_index)
{
    // TODO: handle LGTKs
    if (key_index > 4)
        return;
    if (wsrd->ws.gak_index != key_index) {
        TRACE(TR_SECURITY, "sec: gak index change old:%u new:%u", wsrd->ws.gak_index, key_index);
        wsrd_storage_store(wsrd);
    }
    wsrd->ws.gak_index = key_index;
}

void ws_check_gtkhash(struct wsrd *wsrd)
{
    bool send_key_request = false;
    bool gtkhash_mismatch;

    for (uint8_t i = 0; i < WS_GTK_COUNT; i++) {
        gtkhash_mismatch = supp_gtkhash_mismatch(&wsrd->supp, wsrd->ws.gtkhash[i], i + 1);
        if (gtkhash_mismatch && ws_gtk_installed(&wsrd->supp.gtks[i]))
            supp_revoke_gtk(&wsrd->supp, i);
        // Skip Key-Request if the change is only a revoked/uninstalled key
        if (gtkhash_mismatch && memzcmp(wsrd->ws.gtkhash[i], sizeof(wsrd->ws.gtkhash[i])))
            send_key_request = true;
    }
    if (send_key_request)
        supp_start_key_request(&wsrd->supp);
}

void ws_set_pan_version(struct wsrd *wsrd, int pan_version)
{
    if (pan_version == wsrd->ws.pan_version)
        return;
    wsrd->ws.pan_version = pan_version;
    dbus_emit_change("PanVersion");
}

/*
 *   Wi-SUN FAN 1.1v09 6.3.4.6.3.2.5 FFN Join State 5: Operational
 * If an FFN receives a PAN Configuration indicating a PAN version number
 * (PANVER-IE) that is greater than (newer than) that already known to the FFN:
 */
static void ws_pan_version_update(struct wsrd *wsrd, uint16_t new_pan_version, const uint8_t gtkhash[4][8],
                                  const struct ws_ind *ind, const struct ws_bs_ie *ie_bs)
{
    // Note: In reconnect state, the PAN ID is not set at this stage.
    if (wsrd->ws.pan_id == 0xffff)
        ws_set_pan_id(wsrd, ind->hdr.pan_id);
    /*
     * 1. The FFN MUST record the new incoming PAN Version as the FFN’s new PAN
     * Version.
     */
    ws_set_pan_version(wsrd, new_pan_version);
    // NOTE: A PAN version change means the BR is alive.
    ws_pan_timeout_update(wsrd);
    /*
     *   Wi-SUN FAN 1.1v09 6.3.2.3.2.6 GTK Hash Information Element (GTKHASH-IE)
     * A Router MUST report the GTK Hash values received with the latest
     * received PAN Version.
     */
    memcpy(wsrd->ws.gtkhash, gtkhash, sizeof(wsrd->ws.gtkhash));
    /*
     *   Wi-SUN FAN 1.1v09 6.3.4.6.3 FFN Discovery / Join
     * A Border Router MUST increment PAN Version (PANVER-IE) and reset its PC
     * Trickle timer when any of the following occurs:
     * [...]
     * c. A change in the FFN GTK (derived key) used for FFN-FFN frame security.
     */
    ws_update_gak_index(wsrd, ind->hdr.key_index);
    /*
     * 2. The FFN must examine the content of the PAN Configuration to
     * determine incoming changes and take appropriate action:
     *
     * a. An FFN MUST implement any changes in Broadcast Schedule indicated by
     * the BS-IE.
     * Note: Handled in ws_recv_pc().
     *
     * b. An FFN MUST confirm that it possesses the correct set of PAN GTKs as
     * indicated by the GTKHASH-IE. If the FFN determines the hash of a GTK in
     * its possession does not match that reported by the Border Router, the
     * FFN MUST execute the security flow (described in section 6.5) to acquire
     * that GTK.
     *
     * Further clarification:
     * Wi-SUN requires a handshake to update the GTKL and remove a key when it
     * is revoked earlier than expected from the Lifetime KDE. Immediately
     * deleting the key based on a GTKHASH change is dangerous because the GTK
     * is more likely to leak than the PTK, and authenticator packets are
     * secured using the PTK.
     *
     * NOTE: In "reconnect" state, on PC RX, a GTKHASH mismatch may occur.
     * However, in that state, we do not have any EAPOL target. Therefore,
     * we delay the processing of the GTKHASH-IE to the next successful
     * parent selection.
     */
    if (!eui64_is_bc(&wsrd->eapol_target_eui64))
        ws_check_gtkhash(wsrd);
    /*
     * d. The FFN MUST store any unknown FFN-Wide or PAN-Wide IEs for inclusion
     * in subsequent PAN Configuration and LFN Configuration frame transmissions
     * by the FFN.
     */
    ws_ie_list_clear(&wsrd->ws.ie_list);
    ws_wh_wide_ies_read(&wsrd->ws.ie_list, ind->ie_hdr.data, ind->ie_hdr.data_size, BIT(WS_FT_PC));
    ws_wp_nested_wide_ies_read(&wsrd->ws.ie_list, ind->ie_wp.data, ind->ie_wp.data_size, BIT(WS_FT_PC));
    join_state_transition(wsrd, WSRD_EVENT_PC_RX);
}

static void ws_recv_pc(struct wsrd *wsrd, struct ws_ind *ind)
{
    bool pan_version_update;
    struct ws_bt_ie ie_bt;
    struct ws_us_ie ie_us;
    struct ws_bs_ie ie_bs;
    uint8_t gtkhash[4][8];
    uint16_t pan_version;

    if (wsrd->ws.pan_id == 0xffff && wsrd->prev_pan_id == 0xffff) {
        TRACE(TR_DROP, "drop %s: PAN ID not yet configured", "15.4");
        return;
    }
    if (ind->hdr.pan_id != wsrd->ws.pan_id && ind->hdr.pan_id != wsrd->prev_pan_id) {
        TRACE(TR_DROP, "drop %s: PAN ID mismatch", "15.4");
        return;
    }
    if (!ind->hdr.key_index) {
        TRACE(TR_DROP, "drop %s: unsecured frame", "15.4");
        return;
    }

    if (!ws_wh_bt_read(ind->ie_hdr.data, ind->ie_hdr.data_size, &ie_bt)) {
        TRACE(TR_DROP, "drop %s: missing BT-IE", "15.4");
        return;
    }
    if (!ws_ie_validate_us(&wsrd->ws.fhss, &ind->ie_wp, &ie_us))
        return;
    if (!ws_ie_validate_bs(&wsrd->ws.fhss, &ind->ie_wp, &ie_bs))
        return;

    // TODO: LFNVER-IE, LGTKHASH-IE, LBC-IE, FFN/PAN-Wide IEs
    if (!ws_wp_nested_panver_read(ind->ie_wp.data, ind->ie_wp.data_size, &pan_version)) {
        TRACE(TR_DROP, "drop %-9s: missing PANVER-IE", "15.4");
        return;
    }
    if (!ws_wp_nested_gtkhash_read(ind->ie_wp.data, ind->ie_wp.data_size, gtkhash)) {
        TRACE(TR_DROP, "drop %-9s: missing GTKHASH-IE", "15.4");
        return;
    }

    /*
     *   Wi-SUN FAN 1.1v09 6.3.4.6.3.1 Usage of Trickle Timers
     * b. A consistent transmission is defined as a PAN Configuration with a
     *    PAN-ID matching that of the receiving FFN and a PANVER-IE /
     *    PAN Version equal to the receiving FFN’s current PAN version.
     * c. An inconsistent transmission is defined as either:
     * [...]
     * ii. A PAN Configuration with PAN-ID matching that of the receiving FFN
     *     and a PANVER-IE / PAN Version that is not equal to the receiving
     *     FFN’s current PAN version.
     */
    if (pan_version != wsrd->ws.pan_version)
        trickle_inconsistent(&wsrd->pc_tkl, NULL);
    else
        trickle_consistent(&wsrd->pc_tkl);

    pan_version_update = wsrd->ws.pan_version == -1 || seqno_cmp16(pan_version, wsrd->ws.pan_version) > 0;
    if (pan_version_update)
        ws_pan_version_update(wsrd, pan_version, gtkhash, ind, &ie_bs);

    ws_neigh_us_update(&wsrd->ws.fhss, &ind->neigh->fhss,
                       &ie_us.chan_plan, ie_us.dwell_interval);
    ws_neigh_bs_update(&wsrd->ws.fhss, &ind->neigh->fhss, &ie_bs);

    /*
     * We only sync to the parent if the PAN version number is the latest. This
     * helps to avoid a case where the parent sends us a PC with an outdated
     * PAN version.
     */
    if (pan_version_update || (eui64_eq(&wsrd->eapol_target_eui64, &ind->neigh->eui64) &&
                               !wsrd->fhss_bc_synced_to_target && seqno_cmp16(pan_version, wsrd->ws.pan_version) >= 0))
        ws_sync_fhss_bc(wsrd, ind->neigh);
}

static void ws_recv_pcs(struct wsrd *wsrd, struct ws_ind *ind)
{
    struct ws_us_ie ie_us;

    if (ind->hdr.pan_id == 0xffff) {
        TRACE(TR_DROP, "drop %s: missing PAN ID", "15.4");
        return;
    }
    if (wsrd->ws.pan_id != 0xffff && wsrd->ws.pan_id != ind->hdr.pan_id) {
        TRACE(TR_DROP, "drop %s: PAN ID mismatch", "15.4");
        return;
    }
    if (!ws_ie_validate_netname(wsrd->ws.netname, &ind->ie_wp))
        return;
    if (!ws_ie_validate_us(&wsrd->ws.fhss, &ind->ie_wp, &ie_us))
        return;

    ws_neigh_us_update(&wsrd->ws.fhss, &ind->neigh->fhss,
                       &ie_us.chan_plan, ie_us.dwell_interval);

    /*
     *   Wi-SUN FAN 1.1v08 - 6.3.4.6.3.1 Usage of Trickle Timers
     * A consistent transmission is defined as a PAN Configuration Solicit with
     * a PAN-ID matching that of the receiving FFN and a NETNAME-IE / Network
     * Name matching that configured on the receiving FFN.
     */
    trickle_consistent(&wsrd->pcs_tkl);
    /*
     * c. An inconsistent transmission is defined as either:
     * i. A PAN Configuration Solicit with a PAN-ID matching that of the
     *    receiving FFN and a NETNAME-IE / Network Name matching the network
     *    name configured on the receiving FFN.
     */
    trickle_inconsistent(&wsrd->pc_tkl, NULL);
}

void ws_recv_data(struct wsrd *wsrd, struct ws_ind *ind)
{
    struct ws_us_ie ie_us;
    struct mpx_ie ie_mpx;

    if (wsrd->ws.pan_id == 0xffff) {
        TRACE(TR_DROP, "drop %s: PAN ID not yet configured", "15.4");
        return;
    }
    if (eui64_is_bc(&ind->hdr.dst) && ind->hdr.pan_id != wsrd->ws.pan_id) {
        TRACE(TR_DROP, "drop %s: PAN ID mismatch", "15.4");
        return;
    }
    if (!ind->hdr.key_index) {
        TRACE(TR_DROP, "drop %s: unsecured frame", "15.4");
        return;
    }

    if (!mpx_ie_parse(ind->ie_mpx.data, ind->ie_mpx.data_size, &ie_mpx) ||
        ie_mpx.multiplex_id  != MPX_ID_6LOWPAN ||
        ie_mpx.transfer_type != MPX_FT_FULL_FRAME) {
        TRACE(TR_DROP, "drop %s: invalid MPX-IE", "15.4");
        return;
    }

    if (ws_wp_nested_us_read(ind->ie_wp.data, ind->ie_wp.data_size, &ie_us)) {
        if (!ws_ie_validate_us(&wsrd->ws.fhss, &ind->ie_wp, &ie_us))
            return;
        ws_neigh_us_update(&wsrd->ws.fhss, &ind->neigh->fhss,
                           &ie_us.chan_plan, ie_us.dwell_interval);
    }

    lowpan_recv(&wsrd->ipv6,
                ie_mpx.frame_ptr, ie_mpx.frame_length,
                &ind->hdr.src, &ind->hdr.dst);
}

void ws_recv_eapol(struct wsrd *wsrd, struct ws_ind *ind)
{
    const struct ipv6_neigh *parent;
    struct iobuf_read buf = { };
    struct in6_addr dodag_id;
    struct eui64 auth_eui64;
    struct ws_us_ie ie_us;
    struct ws_bs_ie ie_bs;
    struct ws_bt_ie ie_bt;
    struct mpx_ie ie_mpx;
    uint8_t kmp_id;
    bool has_ea_ie;
    bool has_bs_ie;

    if (wsrd->ws.pan_id == 0xffff) {
        TRACE(TR_DROP, "drop %s: PAN ID not yet configured", "15.4");
        return;
    }
    has_bs_ie = ws_wp_nested_bs_read(ind->ie_wp.data, ind->ie_wp.data_size, &ie_bs);
    if (has_bs_ie && !ws_ie_validate_bs(&wsrd->ws.fhss, &ind->ie_wp, &ie_bs))
        return;
    // We refuse EAPOL frames with a BS-IE but no BT-IE as it does not make sense
    if (has_bs_ie && !ws_wh_bt_read(ind->ie_hdr.data, ind->ie_hdr.data_size, &ie_bt)) {
        TRACE(TR_DROP, "drop %s: have BS-IE but missing BT-IE", "15.4");
        return;
    }

    if (!mpx_ie_parse(ind->ie_mpx.data, ind->ie_mpx.data_size, &ie_mpx) ||
        ie_mpx.multiplex_id  != MPX_ID_KMP ||
        ie_mpx.transfer_type != MPX_FT_FULL_FRAME) {
        TRACE(TR_DROP, "drop %s: invalid MPX-IE", "15.4");
        return;
    }

    /*
     *   Wi-SUN FAN 1.1v08, 6.3.2.3.5.3 Frames for General Purpose Messaging
     * The EA-IE MUST be included in at least one of the EAPOL EAP [EAP Request
     * / Identify] frames addressed to a SUP. This SHOULD be done as early as
     * possible in the 802.1X messaging flow, but the EA-IE SHOULD NOT be
     * repeated in every EAPOL frame addressed to a SUP.
     */
    has_ea_ie = ws_wh_ea_read(ind->ie_hdr.data, ind->ie_hdr.data_size, auth_eui64.u8);

    if (ws_ie_validate_us(&wsrd->ws.fhss, &ind->ie_wp, &ie_us))
        ws_neigh_us_update(&wsrd->ws.fhss, &ind->neigh->fhss, &ie_us.chan_plan, ie_us.dwell_interval);
    if (has_bs_ie)
        ws_neigh_bs_update(&wsrd->ws.fhss, &ind->neigh->fhss, &ie_bs);

    buf.data = ie_mpx.frame_ptr;
    buf.data_size = ie_mpx.frame_length;
    kmp_id = iobuf_pop_u8(&buf);
    if (buf.err) {
        TRACE(TR_DROP, "drop %-9s: invalid eapol packet", "15.4");
        return;
    }

    /*
     * FIXME: This condition is a bit shaky, but it is not entirely clear how
     * to properly differentiate EAPoL packets for our supplicant from those to
     * be relayed. In particular, we should ensure that our EAPoL target does
     * not change during a transaction.
     */
    if (eui64_eq(&ind->hdr.src, &wsrd->eapol_target_eui64) ||
        eui64_eq(&ind->hdr.src, &wsrd->supp.auth_eui64)) {
        if (!wsrd->fhss_bc_synced_to_target)
            ws_sync_fhss_bc(wsrd, ind->neigh);
        supp_recv_eapol(&wsrd->supp, kmp_id,
                        iobuf_ptr(&buf), iobuf_remaining_size(&buf),
                        has_ea_ie ? &auth_eui64 : NULL);
    } else {
        if (wsrd->ws.eapol_relay_fd < 0) {
            TRACE(TR_TX_ABORT, "drop %s: eapol-relay not started", "15.4");
            return;
        }
        parent = rpl_neigh_get_parent(&wsrd->ipv6, RPL_PATH_CTL_PREFERRED);
        BUG_ON(!parent || !parent->rpl);
        dodag_id = parent->rpl->dio.dodag_id; // -Waddress-of-packed-member
        eapol_relay_send(wsrd->ws.eapol_relay_fd,
                         iobuf_ptr(&buf), iobuf_remaining_size(&buf),
                         &dodag_id, &ind->hdr.src, kmp_id);
    }
}

void ws_on_recv_ind(struct ws_ctx *ws, struct ws_ind *ind)
{
    struct wsrd *wsrd = container_of(ws, struct wsrd, ws);
    struct ws_utt_ie ie_utt;

    BUG_ON(!ws_wh_utt_read(ind->ie_hdr.data, ind->ie_hdr.data_size, &ie_utt));

    switch (ie_utt.message_type) {
    case WS_FT_PA:
        ws_recv_pa(wsrd, ind);
        break;
    case WS_FT_PAS:
        ws_recv_pas(wsrd, ind);
        break;
    case WS_FT_PC:
        ws_recv_pc(wsrd, ind);
        break;
    case WS_FT_PCS:
        ws_recv_pcs(wsrd, ind);
        break;
    case WS_FT_DATA:
        ws_recv_data(wsrd, ind);
        break;
    case WS_FT_EAPOL:
        ws_recv_eapol(wsrd, ind);
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported frame type", "15.4");
        return;
    }
}

void ws_on_recv_cnf(struct ws_ctx *ws, struct ws_cnf *cnf)
{
    struct wsrd *wsrd = container_of(ws, struct wsrd, ws);

    if (cnf->frame_ctx.key_index && cnf->hif->status == HIF_STATUS_SUCCESS)
        supp_update_frame_counter(&wsrd->supp, cnf->frame_ctx.key_index, cnf->hif->frame_counter);
    if (cnf->frame_ctx.type == WS_FT_DATA) {
        if (eui64_is_bc(&cnf->frame_ctx.dst))
            mpl_msg_confirm(&wsrd->ipv6.mpl, (void *)((uintptr_t)cnf->hif->handle + 1));
        else
            ipv6_nud_confirm_ns(&wsrd->ipv6, cnf->hif->handle, cnf->hif->status == HIF_STATUS_SUCCESS);
    }
}

void ws_on_send_pas(struct trickle *tkl, struct timer_group *group)
{
    struct wsrd *wsrd = container_of(tkl, struct wsrd, pas_tkl);

    ws_if_send_pas(&wsrd->ws);
}

void ws_on_send_pa(struct trickle *tkl, struct timer_group *group)
{
    struct wsrd *wsrd = container_of(tkl, struct wsrd, pa_tkl);
    const struct ipv6_neigh *ipv6_parent = rpl_neigh_get_parent(&wsrd->ipv6, RPL_PATH_CTL_PREFERRED);
    const struct ws_neigh *ws_parent;
    uint16_t own_routing_cost;

    BUG_ON(!ipv6_parent);
    ws_parent = ws_neigh_get(&wsrd->ws.neigh_table, &ipv6_parent->eui64);
    BUG_ON(!ws_parent);

    if (!ws_parent->ie_pan.fan_tps_version) {
        TRACE(TR_TX_ABORT, "tx-abort %-9s: parent's PAN metrics are not yet available", tr_ws_frame(WS_FT_PA));
        return;
    }
    own_routing_cost = ws_get_own_routing_cost(wsrd);
    ws_if_send_pa(&wsrd->ws, ws_parent->ie_pan.pan_size, own_routing_cost);
}

void ws_on_send_pcs(struct trickle *tkl, struct timer_group *group)
{
    struct wsrd *wsrd = container_of(tkl, struct wsrd, pcs_tkl);

    BUG_ON(wsrd->ws.pan_id == 0xffff && wsrd->prev_pan_id == 0xffff);

    // Wi-SUN FAN 1.1v09 6.3.1 Constants PCS_MAX
    if (wsrd->pcs_nb == 5) {
        join_state_transition(wsrd, WSRD_EVENT_PC_TIMEOUT);
        return;
    }
    if (wsrd->pcs_nb != -1)
        wsrd->pcs_nb++;
    if (wsrd->ws.pan_id == 0xffff)
        ws_if_send_pcs(&wsrd->ws, wsrd->prev_pan_id);
    else
        ws_if_send_pcs(&wsrd->ws, wsrd->ws.pan_id);
}

/*
 * We may not have our parent's broadcast schedule information yet.
 * However, since we made it to JS 5, we received a PAN configuration from a
 * neighbor. Therefore, the information we sent in PC frames should still be
 * correct.
 */
void ws_on_send_pc(struct trickle *tkl, struct timer_group *group)
{
    struct wsrd *wsrd = container_of(tkl, struct wsrd, pc_tkl);

    ws_if_send_pc(&wsrd->ws);
}

static void ws_on_send_dis_insert_neigh(const struct ws_neigh *neighs[WS_RPL_DIS_UC_CAND_MAX],
                                        const struct ws_neigh *neigh)
{
    int worst_slot = 0;

    BUG_ON(isnan(neigh->rsl_in_dbm_unsecured));
    for (int i = 0; i < WS_RPL_DIS_UC_CAND_MAX; i++) {
        if (!neighs[i]) {
            neighs[i] = neigh;
            return;
        }
        if (neighs[i]->rsl_in_dbm_unsecured < neighs[worst_slot]->rsl_in_dbm_unsecured)
            worst_slot = i;
    }
    if (neigh->rsl_in_dbm_unsecured > neighs[worst_slot]->rsl_in_dbm_unsecured)
        neighs[worst_slot] = neigh;
}

void ws_on_send_dis(struct rfc8415_txalg *txalg)
{
    struct ipv6_ctx *ipv6 = container_of(txalg, struct ipv6_ctx, rpl.dis_txalg);
    const struct ws_neigh *best_rsl_neighs[WS_RPL_DIS_UC_CAND_MAX] = { };
    struct wsrd *wsrd = container_of(ipv6, struct wsrd, ipv6);
    struct in6_addr dst = ipv6_prefix_linklocal;
    struct ipv6_neigh *nce;
    struct ws_neigh *neigh;
    int nb_candidates = 0;

    BUG_ON(!timer_stopped(&ipv6->rpl.parent_update_timer));
    // Ensure we have sent at least one DIS wave before selecting a parent
    if (txalg->c > 0) {
        rpl_update_parents(ipv6);
        nce = rpl_neigh_get_parent(ipv6, RPL_PATH_CTL_PREFERRED);
        if (nce)
            return;
    }
    BUG_ON(wsrd->ws.pan_id == 0xffff);
    /*
     *   Wi-SUN FAN 1.1v08 6.2.3.1.6.3 Upward Route Formation
     * A Router MAY wait for DIO messages, MAY solicit a DIO by issuing a
     * unicast DIS to a likely neighbor, or MAY solicit a DIO by issuing a
     * multicast DIS (as described in [RFC6550]).
     *
     * NOTE: This implementation sends unicast DIS packets to a limited
     * number of neighboring nodes.
     */
    SLIST_FOREACH(neigh, &ipv6->rpl.mrhof.ws_neigh_table->neigh_list, link) {
        // TODO: Determine better creterias to filter out bad candidates (eg.
        // network name, PAN ID, PAN-IE routing metric, RSL...).
        if (!ws_neigh_has_us(&neigh->fhss))
            continue;
        if (neigh->pan_id != 0xffff && neigh->pan_id != wsrd->ws.pan_id)
            continue;
        nce = ipv6_neigh_get_from_eui64(ipv6, &neigh->eui64);
        if ((!nce || !nce->rpl) &&
            neigh->rsl_in_dbm_unsecured < ipv6->rpl.mrhof.device_min_sens_dbm)
            continue;
        if (nce && nce->rpl && rpl_cand_is_acceptable(ipv6, nce) != RPL_CAND_OK)
            continue;
        ws_on_send_dis_insert_neigh(best_rsl_neighs, neigh);
        nb_candidates++;
    }

    for (int i = 0; i < ARRAY_SIZE(best_rsl_neighs); i++)
        if (best_rsl_neighs[i]) {
            ipv6_addr_conv_iid_eui64(dst.s6_addr + 8, best_rsl_neighs[i]->eui64.u8);
            rpl_send_dis(ipv6, &dst);
        }
    if (!nb_candidates || nb_candidates > ARRAY_SIZE(best_rsl_neighs))
        rpl_send_dis(ipv6, &ipv6_addr_all_rpl_nodes_link);
    if (timer_remaining_ms(&ipv6->rpl.dis_txalg.timer_rt) > RPL_PARENT_UPDATE_DELAY_MS) {
        timer_start_rel(&ipv6->timer_group, &ipv6->rpl.parent_update_timer, RPL_PARENT_UPDATE_DELAY_MS);
        TRACE(TR_RPL, "rpl: next parent selection in %"PRIu64"ms", timer_remaining_ms(&ipv6->rpl.parent_update_timer));
    } else {
        TRACE(TR_RPL, "rpl: next parent selection in %"PRIu64"ms", timer_remaining_ms(&ipv6->rpl.dis_txalg.timer_rt));
    }
}

static void ws_set_fhss_uc(struct wsrd *wsrd, const uint8_t chan_mask[WS_CHAN_MASK_LEN])
{
    struct ws_ms_chan_mask ms_chan_mask[FIELD_MAX(WS_MASK_POM_COUNT) + 1] = { 0 };

    rail_fill_ms_chan_masks(&wsrd->ws.rcp, &wsrd->ws.fhss, &wsrd->ws.phy, ms_chan_mask);
    rcp_set_fhss_uc(&wsrd->ws.rcp, wsrd->config.ws_uc_dwell_interval_ms, chan_mask, ms_chan_mask);
}

void ws_fhss_uc_use_rand_fixed_chan(struct wsrd *wsrd)
{
    uint8_t chan_mask[WS_CHAN_MASK_LEN];
    int selected_chan;
    int chan_count;
    int chan_idx;

    BUG_ON(version_older_than(wsrd->ws.rcp.version_api, 2, 14, 0));
    BUG_ON(!memzcmp(wsrd->ws.fhss.uc_chan_mask, sizeof(wsrd->ws.fhss.uc_chan_mask)));
    memcpy(chan_mask, wsrd->ws.fhss.uc_chan_mask, sizeof(chan_mask));

    if (ws_chan_mask_get_fixed(chan_mask) >= 0) {
        ws_set_fhss_uc(wsrd, chan_mask);
        return;
    }

    chan_count = ws_chan_mask_count(chan_mask);
    chan_idx = rand_get_random_in_range(0, chan_count - 1);
    selected_chan = ws_chan_mask_get_num(chan_mask, chan_idx);
    BUG_ON(selected_chan < 0);
    memset(chan_mask, 0, sizeof(chan_mask));
    bitset(chan_mask, selected_chan);
    BUG_ON(ws_chan_mask_get_fixed(chan_mask) < 0);
    ws_set_fhss_uc(wsrd, chan_mask);
}

void ws_fhss_uc_use_default(struct wsrd *wsrd)
{
    BUG_ON(!memzcmp(wsrd->ws.fhss.uc_chan_mask, sizeof(wsrd->ws.fhss.uc_chan_mask)));
    ws_set_fhss_uc(wsrd, wsrd->ws.fhss.uc_chan_mask);
}
