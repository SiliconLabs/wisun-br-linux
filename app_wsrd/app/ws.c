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
#define _GNU_SOURCE
#include <errno.h>

#include "common/specs/ieee802154.h"
#include "common/specs/ieee802159.h"
#include "common/ws/eapol_relay.h"
#include "common/ws/ws_ie.h"
#include "common/ws/ws_ie_validation.h"
#include "common/ws/ws_interface.h"
#include "common/ws/ws_regdb.h"
#include "common/ws/ws_types.h"
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
#include "app_wsrd/ipv6/6lowpan.h"
#include "app_wsrd/ipv6/ipv6_addr_mc.h"
#include "app_wsrd/app/join_state.h"
#include "app_wsrd/app/wsrd.h"

#include "ws.h"

/*
 *   Wi-SUN FAN1.1v09 6.3.2.3.2.3 PAN Information Element (PAN-IE)
 * The Routing Cost field is a 16 bit unsigned integer which MUST be set to an
 * estimate of the transmitting node’s routing path ETX to the Border Router.
 * This value is calculated as the transmitting node’s ETX to its routing parent
 * added to the Routing Cost reported by that parent [...].
 */
static uint16_t ws_get_own_routing_cost(struct wsrd *wsrd)
{
    const struct ipv6_neigh *ipv6_parent = rpl_neigh_pref_parent(&wsrd->ipv6);
    const struct ws_neigh *ws_parent;

    if (!ipv6_parent)
        return 0xffff;
    ws_parent = ws_neigh_get(&wsrd->ws.neigh_table, &ipv6_parent->eui64);
    BUG_ON(!ws_parent);

    // Note: overflow during float to int conversion is undefined behavior
    if (ws_parent->ie_pan.routing_cost + (uint16_t)ws_parent->etx > 0xffff)
        return 0xffff;
    return ws_parent->ie_pan.routing_cost + (uint16_t)ws_parent->etx;
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
         *   Wi-SUN FAN 1.1v08, 17 Appendix K EAPOL Target Selection
         * From the set of EAPOL candidates with an RSSI exceeding the threshold
         * of DEVICE_MIN_SENS + CAND_PARENT_THRESHOLD + CAND_PARENT_HYSTERESIS,
         * a joining node should select the EAPOL candidate with lowest PAN Cost
         * as its EAPOL target node.
         */
        if (!candidate->last_pa_rx_time_s ||
            candidate->rsl_in_dbm_unsecured < rail_config->sensitivity_dbm + WS_CAND_PARENT_THRESHOLD_DB +
            WS_CAND_PARENT_HYSTERESIS_DB)
            continue;
        if (!selected_candidate)
            selected_candidate = candidate;
        if (candidate->plf != 0xff && candidate->plf < selected_candidate->plf)
            selected_candidate = candidate;
        else if (ws_neigh_get_pan_cost(candidate) < ws_neigh_get_pan_cost(selected_candidate))
            selected_candidate = candidate;
    }
    if (!selected_candidate)
        return;
    selected_pan_id = selected_candidate->pan_id;

    // Ensure we select the candidate with the lowest pan cost
    SLIST_FOREACH(candidate, &wsrd->ws.neigh_table.neigh_list, link) {
        if (!candidate->last_pa_rx_time_s || candidate->pan_id != selected_pan_id ||
            candidate->rsl_in_dbm_unsecured < rail_config->sensitivity_dbm + WS_CAND_PARENT_THRESHOLD_DB +
            WS_CAND_PARENT_HYSTERESIS_DB)
            continue;
        if (ws_neigh_get_pan_cost(candidate) < ws_neigh_get_pan_cost(selected_candidate))
            selected_candidate = candidate;
    }

    memcpy(&wsrd->eapol_target_eui64, selected_candidate->eui64.u8, sizeof(selected_candidate->eui64.u8));
    // TODO: reset PAN ID when transitioning to join state 1
    wsrd->ws.pan_id = selected_pan_id;
    rcp_set_filter_pan_id(&wsrd->ws.rcp, wsrd->ws.pan_id);
    dbus_emit_change("PanId");
    INFO("eapol target candidate %-7s %s pan_id:0x%04x pan_cost:%u plf:%u%%", "select",
         tr_eui64(selected_candidate->eui64.u8), selected_candidate->pan_id,
         ws_neigh_get_pan_cost(selected_candidate), selected_candidate->plf);
    SLIST_FOREACH(candidate, &wsrd->ws.neigh_table.neigh_list, link)
        candidate->last_pa_rx_time_s = 0;
    join_state_transition(wsrd, WSRD_EVENT_PA_FROM_NEW_PAN);
}

/*
 *   Wi-SUN FAN 1.1v08, 6.3.4.6.3.2.1 FFN Join State 1: Select PAN
 * 1. The set of FFNs from which the joining FFN receives an acceptable PA
 * within DISC_IMIN of the end of the previous PAS interval.
 */
void ws_on_pas_interval_done(struct trickle *tkl)
{
    struct wsrd *wsrd = container_of(tkl, struct wsrd, pas_tkl);

    timer_start_rel(NULL, &wsrd->pan_selection_timer, wsrd->pas_tkl.cfg->Imin_ms);
}

static void ws_eapol_target_add(struct wsrd *wsrd, struct ws_ind *ind, struct ws_pan_ie *ie_pan, struct ws_jm_ie *ie_jm)
{
    const struct ws_jm *jm_plf = ws_wp_nested_jm_get_metric(ie_jm, WS_JM_PLF);
    uint32_t pan_cost = ws_neigh_get_pan_cost(ind->neigh);
    bool added = !ind->neigh->last_pa_rx_time_s;

    ind->neigh->pan_id   = ind->hdr.pan_id;
    ind->neigh->last_pa_rx_time_s = time_now_s(CLOCK_MONOTONIC);
    if (jm_plf)
        ind->neigh->plf = *jm_plf->data;
    else
        ind->neigh->plf = 0xff;

    INFO("eapol target candidate %-7s %s pan_id:0x%04x pan_cost:%u plf:%u%%", added ? "add" : "refresh",
         tr_eui64(ind->neigh->eui64.u8), ind->neigh->pan_id, pan_cost, ind->neigh->plf);

    /*
     *   Wi-SUN FAN 1.1v08, 6.3.4.6.3.2.1 FFN Join State 1: Select PAN
     * 2. If no acceptable PA are received with DISC_IMIN of PAS transmission,
     *    the first acceptable PA received before the end of the current PAS
     *    interval is the single EAPOL target to be used.
     */
    if (timer_stopped(&wsrd->pan_selection_timer))
        ws_on_pan_selection_timer_timeout(NULL, &wsrd->pan_selection_timer);
}

void ws_recv_pa(struct wsrd *wsrd, struct ws_ind *ind)
{
    uint16_t own_routing_cost = ws_get_own_routing_cost(wsrd);
    struct ws_pan_ie ie_pan;
    struct ws_us_ie ie_us;
    struct ws_jm_ie ie_jm;
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

    ws_neigh_us_update(&wsrd->ws.fhss, &ind->neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);

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

    if (eui64_is_bc(&wsrd->eapol_target_eui64))
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
    if (!memzcmp(wsrd->ws.jm.metrics, sizeof(wsrd->ws.jm.metrics)) ||
        seqno_cmp8(ie_jm.version, wsrd->ws.jm.version) > 0)
        wsrd->ws.jm = ie_jm;
}

static void ws_recv_pas(struct wsrd *wsrd, struct ws_ind *ind)
{
    struct ws_us_ie ie_us;

    if (!ws_ie_validate_netname(wsrd->ws.netname, &ind->ie_wp))
        return;
    if (!ws_ie_validate_us(&wsrd->ws.fhss, &ind->ie_wp, &ie_us))
        return;

    ws_neigh_us_update(&wsrd->ws.fhss, &ind->neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);

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
    trickle_inconsistent(&wsrd->pa_tkl);
}

static void ws_chan_params_from_ie(const struct ws_generic_channel_info *ie, struct chan_params *params)
{
    memset(params, 0, sizeof(*params));
    params->reg_domain = REG_DOMAIN_UNDEF;
    switch (ie->channel_plan) {
    case 0:
        *params = *ws_regdb_chan_params(ie->plan.zero.regulatory_domain, 0, ie->plan.zero.operating_class);
        break;
    case 1:
        params->chan0_freq   = ie->plan.one.ch0 * 1000;
        params->chan_spacing = ws_regdb_chan_spacing_from_id(ie->plan.one.channel_spacing);
        params->chan_count   = ie->plan.one.number_of_channel;
        break;
    case 2:
        *params = *ws_regdb_chan_params(ie->plan.two.regulatory_domain, ie->plan.two.channel_plan_id, 0);
        break;
    }
}

static void ws_update_gak_index(struct ws_ctx *ws, uint8_t key_index)
{
    // TODO: handle LGTKs
    if (key_index > 4)
        return;
    if (ws->gak_index != key_index)
        TRACE(TR_SECURITY, "sec: gak index change old:%u new:%u", ws->gak_index, key_index);
    ws->gak_index = key_index;
}

static void ws_recv_pc(struct wsrd *wsrd, struct ws_ind *ind)
{
    struct ipv6_neigh *parent = rpl_neigh_pref_parent(&wsrd->ipv6);
    int cur_pan_version = wsrd->ws.pan_version;
    uint8_t bc_chan_mask[WS_CHAN_MASK_LEN];
    struct chan_params chan_params;
    struct ws_bt_ie ie_bt;
    struct ws_us_ie ie_us;
    struct ws_bs_ie ie_bs;
    uint8_t gtkhash[4][8];
    uint16_t pan_version;

    if (wsrd->ws.pan_id == 0xffff) {
        TRACE(TR_DROP, "drop %s: PAN ID not yet configured", "15.4");
        return;
    }
    if (ind->hdr.pan_id != wsrd->ws.pan_id) {
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
    ws_update_gak_index(&wsrd->ws, ind->hdr.key_index);

    /*
     * Wi-SUN requires a handshake to update the GTKL and remove a key when it
     * is revoked earlier than expected from the Lifetime KDE. Immediately
     * deleting the key based on a GTKHASH change is dangerous because the GTK
     * is more likely to leak than the PTK, and authenticator packets are
     * secured using the PTK.
     */
    for (int i = 0; i < ARRAY_SIZE(gtkhash); i++)
        if (supp_gtkhash_mismatch(&wsrd->supp, gtkhash[i], i + 1))
            supp_start_key_request(&wsrd->supp);
    // TODO: Handle change of PAN version, see Wi-SUN FAN 1.1v08 - 6.3.4.6.3.2.5 FFN Join State 5: Operational
    if (cur_pan_version != pan_version) {
        wsrd->ws.pan_version = pan_version;
        join_state_transition(wsrd, WSRD_EVENT_PC_RX);
        dbus_emit_change("PanVersion");
    }

    ws_neigh_us_update(&wsrd->ws.fhss, &ind->neigh->fhss_data,           &ie_us.chan_plan, ie_us.dwell_interval);
    ws_neigh_us_update(&wsrd->ws.fhss, &ind->neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);

    // TODO: only update on BS-IE change, or parent change
    ws_chan_params_from_ie(&ie_bs.chan_plan, &chan_params);
    ws_chan_mask_calc_reg(bc_chan_mask, &chan_params, HIF_REG_NONE);
    if (!parent || !memcmp(&parent->eui64, &ind->neigh->eui64, 8))
        rcp_set_fhss_ffn_bc(&wsrd->ws.rcp,
                            ie_bs.broadcast_interval,
                            ie_bs.broadcast_schedule_identifier,
                            ie_bs.dwell_interval,
                            bc_chan_mask,
                            ind->hif->timestamp_us,
                            ie_bt.broadcast_slot_number,
                            ie_bt.broadcast_interval_offset,
                            ind->neigh->eui64.u8,
                            ind->neigh->frame_counter_min);
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

    ws_neigh_us_update(&wsrd->ws.fhss, &ind->neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);
    ws_neigh_us_update(&wsrd->ws.fhss, &ind->neigh->fhss_data, &ie_us.chan_plan, ie_us.dwell_interval);

    /*
     *   Wi-SUN FAN 1.1v08 - 6.3.4.6.3.1 Usage of Trickle Timers
     * A consistent transmission is defined as a PAN Configuration Solicit with
     * a PAN-ID matching that of the receiving FFN and a NETNAME-IE / Network
     * Name matching that configured on the receiving FFN.
     */
    trickle_consistent(&wsrd->pcs_tkl);
}

void ws_recv_data(struct wsrd *wsrd, struct ws_ind *ind)
{
    struct ws_us_ie ie_us;
    struct ws_bt_ie ie_bt;
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
    if (!ws_wh_bt_read(ind->ie_hdr.data, ind->ie_hdr.data_size, &ie_bt)) {
        TRACE(TR_DROP, "drop %s: missing BT-IE", "15.4");
        return;
    }

    if (!mpx_ie_parse(ind->ie_mpx.data, ind->ie_mpx.data_size, &ie_mpx) ||
        ie_mpx.multiplex_id  != MPX_ID_6LOWPAN ||
        ie_mpx.transfer_type != MPX_FT_FULL_FRAME) {
        TRACE(TR_DROP, "drop %s: invalid MPX-IE", "15.4");
        return;
    }

    if (ws_ie_validate_us(&wsrd->ws.fhss, &ind->ie_wp, &ie_us)) {
        ws_neigh_us_update(&wsrd->ws.fhss, &ind->neigh->fhss_data,           &ie_us.chan_plan, ie_us.dwell_interval);
        ws_neigh_us_update(&wsrd->ws.fhss, &ind->neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);
    }

    /*
     * We may receive a data frame encrypted with a newly activated GTK prior to
     * receiving a PC.
     */
    ws_update_gak_index(&wsrd->ws, ind->hdr.key_index);

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
    struct mpx_ie ie_mpx;
    uint8_t kmp_id;
    bool has_ea_ie;

    if (wsrd->ws.pan_id == 0xffff) {
        TRACE(TR_DROP, "drop %s: PAN ID not yet configured", "15.4");
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

    if (ws_ie_validate_us(&wsrd->ws.fhss, &ind->ie_wp, &ie_us)) {
        ws_neigh_us_update(&wsrd->ws.fhss, &ind->neigh->fhss_data,           &ie_us.chan_plan, ie_us.dwell_interval);
        ws_neigh_us_update(&wsrd->ws.fhss, &ind->neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);
    }

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
    if (eui64_eq(&ind->hdr.src, &wsrd->eapol_target_eui64)) {
        supp_recv_eapol(&wsrd->supp, kmp_id,
                        iobuf_ptr(&buf), iobuf_remaining_size(&buf),
                        has_ea_ie ? &auth_eui64 : NULL);
    } else {
        if (wsrd->ws.eapol_relay_fd < 0) {
            TRACE(TR_TX_ABORT, "drop %s: eapol-relay not started", "15.4");
            return;
        }
        parent = rpl_neigh_pref_parent(&wsrd->ipv6);
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

void ws_on_recv_cnf(struct ws_ctx *ws, struct ws_frame_ctx *frame_ctx, const struct rcp_tx_cnf *cnf)
{
    struct wsrd *wsrd = container_of(ws, struct wsrd, ws);

    if (frame_ctx->type == WS_FT_DATA)
        ipv6_nud_confirm_ns(&wsrd->ipv6, cnf->handle, cnf->status == HIF_STATUS_SUCCESS);
}

void ws_on_send_pas(struct trickle *tkl)
{
    struct wsrd *wsrd = container_of(tkl, struct wsrd, pas_tkl);

    ws_if_send_pas(&wsrd->ws);
}

void ws_on_send_pa(struct trickle *tkl)
{
    struct wsrd *wsrd = container_of(tkl, struct wsrd, pa_tkl);
    const struct ipv6_neigh *ipv6_parent = rpl_neigh_pref_parent(&wsrd->ipv6);
    uint16_t own_routing_cost = ws_get_own_routing_cost(wsrd);
    const struct ws_neigh *ws_parent;

    BUG_ON(!ipv6_parent);
    ws_parent = ws_neigh_get(&wsrd->ws.neigh_table, &ipv6_parent->eui64);
    BUG_ON(!ws_parent);

    ws_if_send_pa(&wsrd->ws, ws_parent->ie_pan.pan_size, own_routing_cost);
}

void ws_on_send_pcs(struct trickle *tkl)
{
    struct wsrd *wsrd = container_of(tkl, struct wsrd, pcs_tkl);

    // Wi-SUN FAN 1.1v09 6.3.1 Constants PCS_MAX
    if (wsrd->pcs_nb == 5) {
        join_state_transition(wsrd, WSRD_EVENT_PC_TIMEOUT);
        return;
    }
    if (wsrd->pcs_nb != -1)
        wsrd->pcs_nb++;
    ws_if_send_pcs(&wsrd->ws);
}
