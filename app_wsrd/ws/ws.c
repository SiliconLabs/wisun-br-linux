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
#include "common/hif.h"
#include "common/ieee802154_frame.h"
#include "common/ieee802154_ie.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/memutils.h"
#include "common/mpx.h"
#include "common/named_values.h"
#include "common/dbus.h"
#include "common/rcp_api.h"
#include "common/sys_queue_extra.h"
#include "common/ws_ie.h"
#include "common/ws_regdb.h"
#include "common/ws_types.h"
#include "common/time_extra.h"
#include "app_wsrd/ipv6/6lowpan.h"
#include "app_wsrd/ipv6/ipv6_addr.h"

#include "ws.h"

struct ws_ind {
    const struct rcp_rx_ind *hif;
    struct ieee802154_hdr hdr;
    struct iobuf_read ie_hdr;
    struct iobuf_read ie_wp;
    struct iobuf_read ie_mpx;
    struct ws_neigh *neigh;
};

static const struct name_value ws_frames[] = {
    { "adv",       WS_FT_PA },
    { "adv-sol",   WS_FT_PAS },
    { "cfg",       WS_FT_PC },
    { "cfg-sol",   WS_FT_PCS },
    { "data",      WS_FT_DATA },
    { "ack",       WS_FT_ACK },
    { "eapol",     WS_FT_EAPOL },
    { "l-adv",     WS_FT_LPA },
    { "l-adv-sol", WS_FT_LPAS },
    { "l-cfg",     WS_FT_LPC },
    { "l-cfg-sol", WS_FT_LPCS },
    { "l-tsync",   WS_FT_LTS },
    { NULL },
};

static const char *tr_ws_frame(uint8_t type)
{
    return val_to_str(type, ws_frames, "unknown");
}

static bool ws_ie_validate_chan_plan(struct ws_ctx *ws, const struct ws_generic_channel_info *schedule)
{
    const struct ws_channel_plan_zero *plan0 = &schedule->plan.zero;
    const struct ws_channel_plan_one *plan1 = &schedule->plan.one;
    const struct ws_channel_plan_two *plan2 = &schedule->plan.two;
    const struct chan_params *parms = NULL;
    int plan_nr = schedule->channel_plan;

    if (plan_nr == 1)
        return plan1->ch0 * 1000      == ws->fhss.chan_params->chan0_freq &&
               plan1->channel_spacing == ws_regdb_chan_spacing_id(ws->fhss.chan_params->chan_spacing);
    if (plan_nr == 0)
        parms = ws_regdb_chan_params(plan0->regulatory_domain,
                                     0, plan0->operating_class);
    if (plan_nr == 2)
        parms = ws_regdb_chan_params(plan2->regulatory_domain,
                                     plan2->channel_plan_id, 0);
    if (!parms)
        return false;
    return parms->chan0_freq   == ws->fhss.chan_params->chan0_freq &&
           parms->chan_spacing == ws->fhss.chan_params->chan_spacing;
}

static bool ws_ie_validate_schedule(struct ws_ctx *ws, const struct ws_generic_channel_info *schedule)
{
    if (!ws_ie_validate_chan_plan(ws, schedule)) {
        TRACE(TR_DROP, "drop %-9s: invalid channel plan", "15.4");
        return false;
    }

    switch (schedule->channel_function) {
    case WS_CHAN_FUNC_FIXED:
        if (schedule->function.zero.fixed_channel >= 8 * WS_CHAN_MASK_LEN) {
            TRACE(TR_DROP, "drop %-9s: fixed channel >= %u", "15.4", 8 * WS_CHAN_MASK_LEN);
            return false;
        }
        break;
    case WS_CHAN_FUNC_TR51CF:
    case WS_CHAN_FUNC_DH1CF:
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported channel function", "15.4");
        return false;
    }

    switch (schedule->excluded_channel_ctrl) {
    case WS_EXC_CHAN_CTRL_NONE:
    case WS_EXC_CHAN_CTRL_RANGE:
    case WS_EXC_CHAN_CTRL_BITMASK:
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported excluded channel control", "15.4");
        return false;
    }
    return true;
}

static bool ws_ie_validate_us(struct ws_ctx *ws, const struct iobuf_read *ie_wp, struct ws_us_ie *ie_us)
{
    if (!ws_wp_nested_us_read(ie_wp->data, ie_wp->data_size, ie_us)) {
        TRACE(TR_DROP, "drop %-9s: missing US-IE", "15.4");
        return false;
    }
    if (ie_us->chan_plan.channel_function != WS_CHAN_FUNC_FIXED && !ie_us->dwell_interval) {
        TRACE(TR_DROP, "drop %-9s: invalid dwell interval", "15.4");
        return false;
    }
    return ws_ie_validate_schedule(ws, &ie_us->chan_plan);
}

static bool ws_ie_validate_bs(struct ws_ctx *ws, const struct iobuf_read *ie_wp, struct ws_bs_ie *ie_bs)
{
    if (!ws_wp_nested_bs_read(ie_wp->data, ie_wp->data_size, ie_bs)) {
        TRACE(TR_DROP, "drop %-9s: missing BS-IE", "15.4");
        return false;
    }
    return ws_ie_validate_schedule(ws, &ie_bs->chan_plan);
}

static bool ws_ie_validate_netname(struct ws_ctx *ws, const struct iobuf_read *ie_wp)
{
    struct ws_netname_ie ie_netname;

    if (!ws_wp_nested_netname_read(ie_wp->data, ie_wp->data_size, &ie_netname)) {
        TRACE(TR_DROP, "drop %-9s: missing NETNAME-IE", "15.4");
        return false;
    }
    if (strcmp(ws->netname, ie_netname.netname)) {
        TRACE(TR_DROP, "drop %-9s: NETNAME-IE mismatch", "15.4");
        return false;
    }
    return true;
}

static bool ws_ie_validate_pan(struct ws_ctx *ws, const struct iobuf_read *ie_wp, struct ws_pan_ie *ie_pan)
{
    if (!ws_wp_nested_pan_read(ie_wp->data, ie_wp->data_size, ie_pan)) {
        TRACE(TR_DROP, "drop %-9s: missing PAN-IE", "15.4");
        return false;
    }
    if (!ie_pan->routing_method) {
        TRACE(TR_DROP, "drop %-9s: unsupported routing method", "15.4");
        return false;
    }
    if (!ie_pan->use_parent_bs_ie)
        TRACE(TR_IGNORE, "ignore %-9s: unsupported local broadcast", "15.4");
    return true;
}

void ws_on_pan_selection_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct ws_ctx *ws = container_of(timer, struct ws_ctx, pan_selection_timer);
    const struct rcp_rail_config *rail_config = &ws->rcp.rail_config_list[ws->phy.rcp_rail_config_index];
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
    SLIST_FOREACH(candidate, &ws->neigh_table.neigh_list, link) {
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
        else if (candidate->pan_cost < selected_candidate->pan_cost)
            selected_candidate = candidate;
    }
    if (!selected_candidate)
        return;
    selected_pan_id = selected_candidate->pan_id;

    // Ensure we select the candidate with the lowest pan cost
    SLIST_FOREACH(candidate, &ws->neigh_table.neigh_list, link) {
        if (!candidate->last_pa_rx_time_s || candidate->pan_id != selected_pan_id ||
            candidate->rsl_in_dbm_unsecured < rail_config->sensitivity_dbm + WS_CAND_PARENT_THRESHOLD_DB +
            WS_CAND_PARENT_HYSTERESIS_DB)
            continue;
        if (candidate->pan_cost < selected_candidate->pan_cost)
            selected_candidate = candidate;
    }

    trickle_stop(&ws->pas_tkl);
    memcpy(ws->eapol_target_eui64, selected_candidate->mac64, sizeof(selected_candidate->mac64));
    // TODO: reset PAN ID when transitioning to join state 1
    ws->pan_id = selected_pan_id;
    rcp_set_filter_pan_id(&ws->rcp, ws->pan_id);
    dbus_emit_change("PanId");
    INFO("eapol target candidate %-7s %s pan_id:0x%04x pan_cost:%u plf:%u%%", "select",
         tr_eui64(selected_candidate->mac64), selected_candidate->pan_id,
         selected_candidate->pan_cost, selected_candidate->plf);
    SLIST_FOREACH(candidate, &ws->neigh_table.neigh_list, link)
        candidate->last_pa_rx_time_s = 0;
    supp_start_key_request(&ws->supp);
}

/*
 *   Wi-SUN FAN 1.1v08, 6.3.4.6.3.2.1 FFN Join State 1: Select PAN
 * 1. The set of FFNs from which the joining FFN receives an acceptable PA
 * within DISC_IMIN of the end of the previous PAS interval.
 */
void ws_on_pas_interval_done(struct trickle *tkl)
{
    struct ws_ctx *ws = container_of(tkl, struct ws_ctx, pas_tkl);

    timer_start_rel(NULL, &ws->pan_selection_timer, ws->pas_tkl.cfg->Imin_ms);
}

static void ws_eapol_target_add(struct ws_ctx *ws, struct ws_ind *ind, struct ws_pan_ie *ie_pan, struct ws_jm_ie *ie_jm)
{
    bool added = !ind->neigh->last_pa_rx_time_s;

    /*
     *   Wi-SUN FAN 1.1v08, 6.3.4.6.3.2.1 FFN Join State 1: Select PAN
     * PanCost = (PanRoutingCost / PRC_WEIGHT_FACTOR) + (PanSize / PS_WEIGHT_FACTOR)
     *
     * where,
     * PRC_WEIGHT_FACTOR = 256
     * PS_WEIGHT_FACTOR  = 64
     */
    ind->neigh->pan_cost = ie_pan->routing_cost / 256 + ie_pan->pan_size / 64;
    ind->neigh->pan_id   = ind->hdr.pan_id;
    ind->neigh->last_pa_rx_time_s = time_now_s(CLOCK_MONOTONIC);
    if (ie_jm->mask & BIT(WS_JM_PLF))
        ind->neigh->plf = ie_jm->plf;
    else
        ind->neigh->plf = 0xff;

    INFO("eapol target candidate %-7s %s pan_id:0x%04x pan_cost:%u plf:%u%%", added ? "add" : "refresh",
         tr_eui64(ind->neigh->mac64), ind->neigh->pan_id, ind->neigh->pan_cost, ind->neigh->plf);

    /*
     *   Wi-SUN FAN 1.1v08, 6.3.4.6.3.2.1 FFN Join State 1: Select PAN
     * 2. If no acceptable PA are received with DISC_IMIN of PAS transmission,
     *    the first acceptable PA received before the end of the current PAS
     *    interval is the single EAPOL target to be used.
     */
    if (timer_stopped(&ws->pan_selection_timer))
        ws_on_pan_selection_timer_timeout(NULL, &ws->pan_selection_timer);
}

void ws_recv_pa(struct ws_ctx *ws, struct ws_ind *ind)
{
    struct ws_utt_ie ie_utt;
    struct ws_pan_ie ie_pan;
    struct ws_us_ie ie_us;
    struct ws_jm_ie ie_jm;

    if (ind->hdr.pan_id == 0xffff) {
        TRACE(TR_DROP, "drop %s: missing PAN ID", "15.4");
        return;
    }
    if (ws->pan_id != 0xffff && ws->pan_id != ind->hdr.pan_id) {
        TRACE(TR_DROP, "drop %s: PAN ID mismatch", "15.4");
        return;
    }
    ws_wh_utt_read(ind->ie_hdr.data, ind->ie_hdr.data_size, &ie_utt);
    if (!ws_ie_validate_netname(ws, &ind->ie_wp))
        return;
    if (!ws_ie_validate_pan(ws, &ind->ie_wp, &ie_pan))
        return;
    if (!ws_ie_validate_us(ws, &ind->ie_wp, &ie_us))
        return;
    ws_wp_nested_jm_read(ind->ie_wp.data, ind->ie_wp.data_size, &ie_jm);

    ws_neigh_ut_update(&ind->neigh->fhss_data_unsecured, ie_utt.ufsi, ind->hif->timestamp_us, ind->hdr.src);
    ws_neigh_us_update(&ws->fhss, &ind->neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);

    // TODO: POM-IE

    if (!memcmp(ws->eapol_target_eui64, ieee802154_addr_bc, sizeof(ws->eapol_target_eui64)))
        ws_eapol_target_add(ws, ind, &ie_pan, &ie_jm);
}

static void ws_recv_pas(struct ws_ctx *ws, struct ws_ind *ind)
{
    struct ws_utt_ie ie_utt;
    struct ws_us_ie ie_us;

    if (!ws_ie_validate_netname(ws, &ind->ie_wp))
        return;
    if (!ws_ie_validate_us(ws, &ind->ie_wp, &ie_us))
        return;

    ws_wh_utt_read(ind->ie_hdr.data, ind->ie_hdr.data_size, &ie_utt);
    ws_neigh_ut_update(&ind->neigh->fhss_data_unsecured, ie_utt.ufsi, ind->hif->timestamp_us, ind->hdr.src);
    ws_neigh_us_update(&ws->fhss, &ind->neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);

    /*
     *   Wi-SUN FAN 1.1v08 - 6.3.4.6.3.1 Usage of Trickle Timers
     * A consistent transmission is defined as a PAN Advertisement Solicit with
     * NETNAME-IE / Network Name matching that configured on the FFN.
     */
    trickle_consistent(&ws->pas_tkl);
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

static void ws_recv_pc(struct ws_ctx *ws, struct ws_ind *ind)
{
    uint8_t bc_chan_mask[WS_CHAN_MASK_LEN];
    struct chan_params chan_params;
    struct ws_utt_ie ie_utt;
    struct ws_bt_ie ie_bt;
    struct ws_us_ie ie_us;
    struct ws_bs_ie ie_bs;
    uint8_t gtkhash[4][8];
    uint16_t pan_version;

    if (ws->pan_id == 0xffff) {
        TRACE(TR_DROP, "drop %s: PAN ID not yet configured", "15.4");
        return;
    }
    if (ind->hdr.pan_id != ws->pan_id) {
        TRACE(TR_DROP, "drop %s: PAN ID mismatch", "15.4");
        return;
    }
    if (!ind->hdr.key_index) {
        TRACE(TR_DROP, "drop %s: unsecured frame", "15.4");
        return;
    }

    ws_wh_utt_read(ind->ie_hdr.data, ind->ie_hdr.data_size, &ie_utt);
    if (!ws_wh_bt_read(ind->ie_hdr.data, ind->ie_hdr.data_size, &ie_bt)) {
        TRACE(TR_DROP, "drop %s: missing BT-IE", "15.4");
        return;
    }
    if (!ws_ie_validate_us(ws, &ind->ie_wp, &ie_us))
        return;
    if (!ws_ie_validate_bs(ws, &ind->ie_wp, &ie_bs))
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
    ws_update_gak_index(ws, ind->hdr.key_index);

    for (int i = 0; i < ARRAY_SIZE(gtkhash); i++)
        if (!supp_has_gtk(&ws->supp, gtkhash[i], i + 1))
            supp_start_key_request(&ws->supp);
    // TODO: Handle change of PAN version, see Wi-SUN FAN 1.1v08 - 6.3.4.6.3.2.5 FFN Join State 5: Operational
    if (ws->pan_version < 0)
        rpl_start_dis(&ws->ipv6);
    if (ws->pan_version != pan_version) {
        ws->pan_version = pan_version;
        trickle_stop(&ws->pcs_tkl);
        dbus_emit_change("PanVersion");
    }

    ws_neigh_ut_update(&ind->neigh->fhss_data,           ie_utt.ufsi, ind->hif->timestamp_us, ind->hdr.src);
    ws_neigh_ut_update(&ind->neigh->fhss_data_unsecured, ie_utt.ufsi, ind->hif->timestamp_us, ind->hdr.src);
    ws_neigh_us_update(&ws->fhss, &ind->neigh->fhss_data,           &ie_us.chan_plan, ie_us.dwell_interval);
    ws_neigh_us_update(&ws->fhss, &ind->neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);

    // TODO: only update on BS-IE change, or parent change
    ws_chan_params_from_ie(&ie_bs.chan_plan, &chan_params);
    ws_chan_mask_calc_reg(bc_chan_mask, &chan_params, HIF_REG_NONE);
    // TODO: use parent address and frame counters only
    rcp_set_fhss_ffn_bc(&ws->rcp,
                        ie_bs.broadcast_interval,
                        ie_bs.broadcast_schedule_identifier,
                        ie_bs.dwell_interval,
                        bc_chan_mask,
                        ind->hif->timestamp_us,
                        ie_bt.broadcast_slot_number,
                        ie_bt.broadcast_interval_offset,
                        ind->neigh->mac64,
                        ind->neigh->frame_counter_min);
}

static void ws_recv_pcs(struct ws_ctx *ws, struct ws_ind *ind)
{
    struct ws_utt_ie ie_utt;
    struct ws_us_ie ie_us;

    if (ind->hdr.pan_id == 0xffff) {
        TRACE(TR_DROP, "drop %s: missing PAN ID", "15.4");
        return;
    }
    if (ws->pan_id != 0xffff && ws->pan_id != ind->hdr.pan_id) {
        TRACE(TR_DROP, "drop %s: PAN ID mismatch", "15.4");
        return;
    }
    if (!ws_ie_validate_netname(ws, &ind->ie_wp))
        return;
    if (!ws_ie_validate_us(ws, &ind->ie_wp, &ie_us))
        return;

    ws_wh_utt_read(ind->ie_hdr.data, ind->ie_hdr.data_size, &ie_utt);
    ws_neigh_ut_update(&ind->neigh->fhss_data_unsecured, ie_utt.ufsi, ind->hif->timestamp_us, ind->hdr.src);
    ws_neigh_ut_update(&ind->neigh->fhss_data, ie_utt.ufsi, ind->hif->timestamp_us, ind->hdr.src);
    ws_neigh_us_update(&ws->fhss, &ind->neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);
    ws_neigh_us_update(&ws->fhss, &ind->neigh->fhss_data, &ie_us.chan_plan, ie_us.dwell_interval);

    /*
     *   Wi-SUN FAN 1.1v08 - 6.3.4.6.3.1 Usage of Trickle Timers
     * A consistent transmission is defined as a PAN Configuration Solicit with
     * a PAN-ID matching that of the receiving FFN and a NETNAME-IE / Network
     * Name matching that configured on the receiving FFN.
     */
    trickle_consistent(&ws->pcs_tkl);
}

void ws_recv_data(struct ws_ctx *ws, struct ws_ind *ind)
{
    struct ws_utt_ie ie_utt;
    struct ws_us_ie ie_us;
    struct mpx_ie ie_mpx;

    if (ws->pan_id == 0xffff) {
        TRACE(TR_DROP, "drop %s: PAN ID not yet configured", "15.4");
        return;
    }
    if (!memcmp(ind->hdr.dst, ieee802154_addr_bc, 8) && ind->hdr.pan_id != ws->pan_id) {
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

    ws_wh_utt_read(ind->ie_hdr.data, ind->ie_hdr.data_size, &ie_utt);
    ws_neigh_ut_update(&ind->neigh->fhss_data,           ie_utt.ufsi, ind->hif->timestamp_us, ind->hdr.src);
    ws_neigh_ut_update(&ind->neigh->fhss_data_unsecured, ie_utt.ufsi, ind->hif->timestamp_us, ind->hdr.src);

    if (ws_ie_validate_us(ws, &ind->ie_wp, &ie_us)) {
        ws_neigh_us_update(&ws->fhss, &ind->neigh->fhss_data,           &ie_us.chan_plan, ie_us.dwell_interval);
        ws_neigh_us_update(&ws->fhss, &ind->neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);
    }

    /*
     * We may receive a data frame encrypted with a newly activated GTK prior to
     * receiving a PC.
     */
    ws_update_gak_index(ws, ind->hdr.key_index);

    lowpan_recv(&ws->ipv6,
                ie_mpx.frame_ptr, ie_mpx.frame_length,
                ind->hdr.src, ind->hdr.dst);
}

void ws_recv_eapol(struct ws_ctx *ws, struct ws_ind *ind)
{
    uint8_t authenticator_eui64[8];
    struct iobuf_read buf = { };
    struct ws_utt_ie ie_utt;
    struct ws_neigh *neigh;
    struct ws_us_ie ie_us;
    struct mpx_ie ie_mpx;
    uint8_t kmp_id;
    bool has_ea_ie;

    if (ws->pan_id == 0xffff) {
        TRACE(TR_DROP, "drop %s: PAN ID not yet configured", "15.4");
        return;
    }

    if (!mpx_ie_parse(ind->ie_mpx.data, ind->ie_mpx.data_size, &ie_mpx) ||
        ie_mpx.multiplex_id  != MPX_ID_KMP ||
        ie_mpx.transfer_type != MPX_FT_FULL_FRAME) {
        TRACE(TR_DROP, "drop %s: invalid MPX-IE", "15.4");
        return;
    }

    neigh = ws_neigh_get(&ws->neigh_table, ind->hdr.src);
    if (!neigh)
        neigh = ws_neigh_add(&ws->neigh_table, ind->hdr.src, WS_NR_ROLE_ROUTER, 16, 0x01);
    else
        ws_neigh_refresh(&ws->neigh_table, neigh, neigh->lifetime_s);

    ws_wh_utt_read(ind->ie_hdr.data, ind->ie_hdr.data_size, &ie_utt);
    ws_neigh_ut_update(&neigh->fhss_data,           ie_utt.ufsi, ind->hif->timestamp_us, ind->hdr.src);
    ws_neigh_ut_update(&neigh->fhss_data_unsecured, ie_utt.ufsi, ind->hif->timestamp_us, ind->hdr.src);

    /*
     *   Wi-SUN FAN 1.1v08, 6.3.2.3.5.3 Frames for General Purpose Messaging
     * The EA-IE MUST be included in at least one of the EAPOL EAP [EAP Request
     * / Identify] frames addressed to a SUP. This SHOULD be done as early as
     * possible in the 802.1X messaging flow, but the EA-IE SHOULD NOT be
     * repeated in every EAPOL frame addressed to a SUP.
     */
    has_ea_ie = ws_wh_ea_read(ind->ie_hdr.data, ind->ie_hdr.data_size, authenticator_eui64);

    if (ws_ie_validate_us(ws, &ind->ie_wp, &ie_us)) {
        ws_neigh_us_update(&ws->fhss, &neigh->fhss_data,           &ie_us.chan_plan, ie_us.dwell_interval);
        ws_neigh_us_update(&ws->fhss, &neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);
    }

    buf.data = ie_mpx.frame_ptr;
    buf.data_size = ie_mpx.frame_length;
    kmp_id = iobuf_pop_u8(&buf);
    if (buf.err) {
        TRACE(TR_DROP, "drop %-9s: invalid eapol packet", "15.4");
        return;
    }

    supp_recv_eapol(&ws->supp, kmp_id, iobuf_ptr(&buf), iobuf_remaining_size(&buf),
                    has_ea_ie ? authenticator_eui64 : NULL);
}

void ws_print_ind(const struct ws_ind *ind, uint8_t type)
{
    unsigned int tr_domain;

    if (type == WS_FT_DATA || type == WS_FT_ACK || type == WS_FT_EAPOL)
        tr_domain = TR_15_4_DATA;
    else
        tr_domain = TR_15_4_MNGT;

    if (ind->hdr.pan_id >= 0 && ind->hdr.pan_id != 0xffff)
        TRACE(tr_domain, "rx-15.4 %-9s src:%s panid:%x (%ddBm)",
              tr_ws_frame(type), tr_eui64(ind->hdr.src),
              ind->hdr.pan_id, ind->hif->rx_power_dbm);
    else
        TRACE(tr_domain, "rx-15.4 %-9s src:%s (%ddBm)",
              tr_ws_frame(type), tr_eui64(ind->hdr.src),
              ind->hif->rx_power_dbm);
}

void ws_recv_ind(struct ws_ctx *ws, const struct rcp_rx_ind *hif_ind)
{
    struct ws_ind ind = { .hif = hif_ind };
    struct iobuf_read ie_payload;
    struct ws_utt_ie ie_utt;
    struct ws_fc_ie ie_fc;
    int ret;

    ret = ieee802154_frame_parse(hif_ind->frame, hif_ind->frame_len,
                                 &ind.hdr, &ind.ie_hdr, &ie_payload);
    if (ret < 0)
        return;

    if (!ws_wh_utt_read(ind.ie_hdr.data, ind.ie_hdr.data_size, &ie_utt)) {
        TRACE(TR_DROP, "drop %-9s: missing UTT-IE", "15.4");
        return;
    }
    // HACK: In FAN 1.0 the source address is elided in EDFE response frames
    if (ws_wh_fc_read(ind.ie_hdr.data, ind.ie_hdr.data_size, &ie_fc)) {
        if (memcmp(ind.hdr.src, ieee802154_addr_bc, 8))
            memcpy(ws->edfe_src, ind.hdr.src, 8);
        else
            memcpy(ind.hdr.src, ws->edfe_src, 8);
    }

    ieee802154_ie_find_payload(ie_payload.data, ie_payload.data_size,
                               IEEE802154_IE_ID_WP, &ind.ie_wp);
    ieee802154_ie_find_payload(ie_payload.data, ie_payload.data_size,
                               IEEE802154_IE_ID_MPX, &ind.ie_mpx);

    ind.neigh = ws_neigh_get(&ws->neigh_table, ind.hdr.src);
    if (!ind.neigh)
        // TODO: TX power (APC), active key indices
        ind.neigh = ws_neigh_add(&ws->neigh_table, ind.hdr.src, WS_NR_ROLE_ROUTER, 16, 0x02);
    else
        ws_neigh_refresh(&ws->neigh_table, ind.neigh, ind.neigh->lifetime_s);
    ind.neigh->rsl_in_dbm_unsecured = ws_neigh_ewma_next(ind.neigh->rsl_in_dbm_unsecured,
                                                         hif_ind->rx_power_dbm);
    if (ind.hdr.key_index)
        ind.neigh->rsl_in_dbm = ws_neigh_ewma_next(ind.neigh->rsl_in_dbm,
                                                   hif_ind->rx_power_dbm);

    ws_print_ind(&ind, ie_utt.message_type);

    switch (ie_utt.message_type) {
    case WS_FT_PA:
        ws_recv_pa(ws, &ind);
        break;
    case WS_FT_PAS:
        ws_recv_pas(ws, &ind);
        break;
    case WS_FT_PC:
        ws_recv_pc(ws, &ind);
        break;
    case WS_FT_PCS:
        ws_recv_pcs(ws, &ind);
        break;
    case WS_FT_DATA:
        ws_recv_data(ws, &ind);
        break;
    case WS_FT_EAPOL:
        ws_recv_eapol(ws, &ind);
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported frame type", "15.4");
        return;
    }
}

static struct ws_frame_ctx *ws_frame_ctx_new(struct ws_ctx *ws, uint8_t type)
{
    struct ws_frame_ctx *cur, *new;

    if ((type == WS_FT_PAS || type == WS_FT_PCS) &&
        SLIST_FIND(cur, &ws->frame_ctx_list, link, cur->type == type)) {
        WARN("%s tx overlap, consider increasing trickle Imin", tr_ws_frame(type));
        TRACE(TR_TX_ABORT, "tx-abort %-9s: tx already in progress", tr_ws_frame(type));
        return NULL;
    }
    if (SLIST_SIZE(&ws->frame_ctx_list, link) > UINT8_MAX) {
        TRACE(TR_TX_ABORT, "tx-abort %-9s: no handle available", tr_ws_frame(type));
        return NULL;
    }

    new = zalloc(sizeof(*new));
    new->handle = ws->handle_next++;
    new->type = type;
    // If next handle is already in use (unlikely), use the next available one.
    while (SLIST_FIND(cur, &ws->frame_ctx_list, link,
                      cur->handle == new->handle))
        new->handle = ws->handle_next++;
    SLIST_INSERT_HEAD(&ws->frame_ctx_list, new, link);
    return new;
}

static struct ws_frame_ctx *ws_frame_ctx_pop(struct ws_ctx *ws, uint8_t handle)
{
    struct ws_frame_ctx *cur;

    cur = SLIST_FIND(cur, &ws->frame_ctx_list, link, cur->handle == handle);
    if (cur)
        SLIST_REMOVE(&ws->frame_ctx_list, cur, ws_frame_ctx, link);
    return cur;
}

void ws_recv_cnf(struct ws_ctx *ws, const struct rcp_tx_cnf *cnf)
{
    struct iobuf_read ie_header, ie_payload;
    struct ws_frame_ctx *frame_ctx;
    struct ws_neigh *neigh = NULL;
    struct ieee802154_hdr hdr;
    int ret, rsl;

    if (cnf->status != HIF_STATUS_SUCCESS)
        TRACE(TR_TX_ABORT, "tx-abort 15.4: status %s", hif_status_str(cnf->status));

    frame_ctx = ws_frame_ctx_pop(ws, cnf->handle);
    if (!frame_ctx) {
        ERROR("unknown frame handle: %u", cnf->handle);
        return;
    }

    if (frame_ctx->type == WS_FT_DATA)
        ipv6_nud_confirm_ns(&ws->ipv6, cnf->handle, cnf->status == HIF_STATUS_SUCCESS);

    if (memcmp(frame_ctx->dst, ieee802154_addr_bc, 8)) {
        neigh = ws_neigh_get(&ws->neigh_table, frame_ctx->dst);
        if (!neigh) {
            WARN("%s: neighbor expired", __func__);
            // TODO: TX power (APC), active key indices
            neigh = ws_neigh_add(&ws->neigh_table, frame_ctx->dst, WS_NR_ROLE_ROUTER, 16, BIT(1));
        }
    }

    free(frame_ctx);

    if (neigh && cnf->frame_len) {
        ret = ieee802154_frame_parse(cnf->frame, cnf->frame_len, &hdr, &ie_header, &ie_payload);
        if (ret < 0) {
            WARN("%s: malformed frame", __func__);
            return;
        }
        // TODO: check frame counter
        neigh->rsl_in_dbm_unsecured = ws_neigh_ewma_next(neigh->rsl_in_dbm_unsecured,
                                                         cnf->rx_power_dbm);
        if (hdr.key_index)
            neigh->rsl_in_dbm = ws_neigh_ewma_next(neigh->rsl_in_dbm, cnf->rx_power_dbm);
        if (ws_wh_rsl_read(ie_header.data, ie_header.data_size, &rsl))
            neigh->rsl_out_dbm = ws_neigh_ewma_next(neigh->rsl_out_dbm, rsl);
    }
    if (neigh)
        ws_neigh_etx_update(&ws->neigh_table, neigh,
                            cnf->tx_retries + 1,
                            cnf->status == HIF_STATUS_SUCCESS);
}

int ws_send_data(struct ws_ctx *ws, const void *pkt, size_t pkt_len, const uint8_t dst[8])
{
    struct ieee802154_hdr hdr = {
        .frame_type = IEEE802154_FRAME_TYPE_DATA,
        .ack_req    = true,
        .seqno      = ws->seqno++, // TODO: think more about how seqno should be handled
        .key_index  = ws->gak_index,
    };
    struct mpx_ie ie_mpx = {
        .transfer_type = MPX_FT_FULL_FRAME,
        .multiplex_id  = MPX_ID_6LOWPAN,
    };
    struct ws_frame_ctx *frame_ctx;
    struct iobuf_write iobuf = { };
    struct ws_neigh *neigh = NULL;
    uint8_t fhss_type;
    int offset;

    if (dst && memcmp(ieee802154_addr_bc, dst, 8)) {
        neigh = ws_neigh_get(&ws->neigh_table, dst);
        if (!neigh) {
            TRACE(TR_TX_ABORT, "tx-abort %-9s: unknown neighbor %s", "15.4", tr_eui64(dst));
            return -ETIMEDOUT;
        }
        memcpy(hdr.dst, dst, 8);
        hdr.pan_id = -1;
        fhss_type = HIF_FHSS_TYPE_FFN_UC;
    } else {
        memcpy(hdr.dst, ieee802154_addr_bc, 8);
        hdr.pan_id = ws->pan_id;
        fhss_type = HIF_FHSS_TYPE_FFN_BC;
    }

    frame_ctx = ws_frame_ctx_new(ws, WS_FT_DATA);
    if (!frame_ctx)
        return -ENOMEM;
    memcpy(frame_ctx->dst, hdr.dst, 8);

    ieee802154_frame_write_hdr(&iobuf, &hdr);

    ws_wh_utt_write(&iobuf, WS_FT_DATA);
    // TODO: BT-IE, LBT-IE
    ieee802154_ie_push_header(&iobuf, IEEE802154_IE_ID_HT1);

    offset = ieee802154_ie_push_payload(&iobuf, IEEE802154_IE_ID_WP);
    if (neigh) // TODO: only include US-IE if 1st unicast frame to neighbor
        ws_wp_nested_us_write(&iobuf, &ws->fhss);
    // TODO: JM-IE
    ieee802154_ie_fill_len_payload(&iobuf, offset);

    offset = ieee802154_ie_push_payload(&iobuf, IEEE802154_IE_ID_MPX);
    mpx_ie_write(&iobuf, &ie_mpx);
    iobuf_push_data(&iobuf, pkt, pkt_len);
    ieee802154_ie_fill_len_payload(&iobuf, offset);

    iobuf_push_data_reserved(&iobuf, 8); // MIC-64

    TRACE(TR_15_4_DATA, "tx-15.4 %-9s dst:%s", tr_ws_frame(WS_FT_DATA), tr_eui64(dst));
    rcp_req_data_tx(&ws->rcp,
                    iobuf.data, iobuf.len,
                    frame_ctx->handle,
                    fhss_type,
                    neigh ? &neigh->fhss_data_unsecured : NULL,
                    neigh ? neigh->frame_counter_min : NULL,
                    NULL, 0);  // TODO: mode switch
    iobuf_free(&iobuf);
    return frame_ctx->handle;
}


void ws_send_eapol(struct ws_ctx *ws, uint8_t kmp_id, const void *pkt, size_t pkt_len, const uint8_t dst[8])
{
    struct ieee802154_hdr hdr = {
        .frame_type = IEEE802154_FRAME_TYPE_DATA,
        .ack_req    = true,
        .seqno      = ws->seqno++, // TODO: think more about how seqno should be handled
        .pan_id     = -1,
    };
    struct mpx_ie ie_mpx = {
        .transfer_type = MPX_FT_FULL_FRAME,
        .multiplex_id  = MPX_ID_KMP,
    };
    struct ws_frame_ctx *frame_ctx;
    struct iobuf_write iobuf = { };
    struct ws_neigh *neigh;
    int offset;

    neigh = ws_neigh_get(&ws->neigh_table, dst);
    if (!neigh) {
        TRACE(TR_TX_ABORT, "tx-abort %-9s: unknown neighbor %s", "15.4", tr_eui64(dst));
        return;
    }

    frame_ctx = ws_frame_ctx_new(ws, WS_FT_EAPOL);
    if (!frame_ctx)
        return;
    memcpy(hdr.dst, dst, 8);
    memcpy(frame_ctx->dst, hdr.dst, 8);

    ieee802154_frame_write_hdr(&iobuf, &hdr);

    ws_wh_utt_write(&iobuf, WS_FT_EAPOL);
    // TODO: BT-IE, LBT-IE
    ieee802154_ie_push_header(&iobuf, IEEE802154_IE_ID_HT1);

    offset = ieee802154_ie_push_payload(&iobuf, IEEE802154_IE_ID_WP);
    // TODO: only include US-IE if 1st unicast frame to neighbor
    ws_wp_nested_us_write(&iobuf, &ws->fhss);
    ieee802154_ie_fill_len_payload(&iobuf, offset);

    offset = ieee802154_ie_push_payload(&iobuf, IEEE802154_IE_ID_MPX);
    mpx_ie_write(&iobuf, &ie_mpx);
    iobuf_push_u8(&iobuf, kmp_id);
    iobuf_push_data(&iobuf, pkt, pkt_len);
    ieee802154_ie_fill_len_payload(&iobuf, offset);

    TRACE(TR_15_4_DATA, "tx-15.4 %-9s dst:%s", tr_ws_frame(WS_FT_EAPOL), tr_eui64(dst));
    rcp_req_data_tx(&ws->rcp,
                    iobuf.data, iobuf.len,
                    frame_ctx->handle,
                    HIF_FHSS_TYPE_FFN_UC,
                    &neigh->fhss_data_unsecured,
                    neigh->frame_counter_min,
                    NULL, 0); // TODO: mode switch
    iobuf_free(&iobuf);
}

void ws_send_pas(struct trickle *tkl)
{
    struct ws_ctx *ws = container_of(tkl, struct ws_ctx, pas_tkl);
    struct ieee802154_hdr hdr = {
        .frame_type   = IEEE802154_FRAME_TYPE_DATA,
        .seqno        = -1,
        .pan_id       = -1,
        .dst[0 ... 7] = 0xff,
    };
    struct ws_frame_ctx *frame_ctx;
    struct iobuf_write iobuf = { };
    int offset;

    frame_ctx = ws_frame_ctx_new(ws, WS_FT_PAS);
    if (!frame_ctx)
        return;
    memcpy(frame_ctx->dst, hdr.dst, 8);

    ieee802154_frame_write_hdr(&iobuf, &hdr);

    ws_wh_utt_write(&iobuf, WS_FT_PAS);
    ieee802154_ie_push_header(&iobuf, IEEE802154_IE_ID_HT1);

    // TODO: POM-IE
    offset = ieee802154_ie_push_payload(&iobuf, IEEE802154_IE_ID_WP);
    ws_wp_nested_us_write(&iobuf, &ws->fhss);
    ws_wp_nested_netname_write(&iobuf, ws->netname);
    ieee802154_ie_fill_len_payload(&iobuf, offset);

    TRACE(TR_15_4_MNGT, "tx-15.4 %-9s", tr_ws_frame(WS_FT_PAS));
    rcp_req_data_tx(&ws->rcp,
                    iobuf.data, iobuf.len,
                    frame_ctx->handle,
                    HIF_FHSS_TYPE_ASYNC,
                    NULL, 0,
                    NULL, 0);
    iobuf_free(&iobuf);
}

void ws_send_pcs(struct trickle *tkl)
{
    struct ws_ctx *ws = container_of(tkl, struct ws_ctx, pcs_tkl);
    struct ieee802154_hdr hdr = {
        .frame_type   = IEEE802154_FRAME_TYPE_DATA,
        .seqno        = -1,
        .pan_id       = ws->pan_id,
        .dst[0 ... 7] = 0xff,
        .key_index    = ws->gak_index,
    };
    struct ws_frame_ctx *frame_ctx;
    struct iobuf_write iobuf = { };
    int offset;

    frame_ctx = ws_frame_ctx_new(ws, WS_FT_PCS);
    if (!frame_ctx)
        return;
    memcpy(frame_ctx->dst, hdr.dst, 8);

    ieee802154_frame_write_hdr(&iobuf, &hdr);

    ws_wh_utt_write(&iobuf, WS_FT_PCS);
    ieee802154_ie_push_header(&iobuf, IEEE802154_IE_ID_HT1);

    offset = ieee802154_ie_push_payload(&iobuf, IEEE802154_IE_ID_WP);
    ws_wp_nested_us_write(&iobuf, &ws->fhss);
    ws_wp_nested_netname_write(&iobuf, ws->netname);
    ieee802154_ie_fill_len_payload(&iobuf, offset);

    TRACE(TR_15_4_MNGT, "tx-15.4 %-9s panid:0x%x", tr_ws_frame(WS_FT_PCS), ws->pan_id);
    rcp_req_data_tx(&ws->rcp,
                    iobuf.data, iobuf.len,
                    frame_ctx->handle,
                    HIF_FHSS_TYPE_ASYNC,
                    NULL, 0,
                    NULL, 0);
    iobuf_free(&iobuf);
}
