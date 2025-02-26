/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#include <time.h>
#include "common/ws/ws_ie.h"
#include "common/log.h"
#include "common/rand.h"
#include "common/trickle_legacy.h"
#include "common/specs/ieee802154.h"
#include "common/specs/ws.h"
#include "common/string_extra.h"

#include "net/timers.h"
#include "ws/ws_pan_info_storage.h"
#include "ws/ws_common.h"
#include "ws/ws_ie_validation.h"
#include "ws/ws_llc.h"

#include "ws_mngt.h"

static bool ws_mngt_ie_utt_validate(const struct mcps_data_rx_ie_list *ie_ext,
                                    struct ws_utt_ie *ie_utt,
                                    uint8_t frame_type)
{
    if (!ws_wh_utt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, ie_utt)) {
        TRACE(TR_DROP, "drop %-9s: missing UTT-IE", tr_ws_frame(frame_type));
        return false;
    }
    BUG_ON(ie_utt->message_type != frame_type);
    return true;
}

static bool ws_mngt_ie_us_validate(struct ws_info *ws_info,
                                   const struct mcps_data_rx_ie_list *ie_ext,
                                   struct ws_us_ie *ie_us,
                                   uint8_t frame_type)
{
    // FIXME: see comment in ws_llc_mngt_ind
    if (!ws_wp_nested_us_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, ie_us)) {
        TRACE(TR_DROP, "drop %-9s: missing US-IE", tr_ws_frame(frame_type));
        return false;
    }
    return ws_ie_validate_us(ws_info, ie_us);
}

static bool ws_mngt_ie_netname_validate(struct ws_info *ws_info,
                                        const struct mcps_data_rx_ie_list *ie_ext,
                                        uint8_t frame_type)
{
    struct ws_netname_ie ie_netname;

    // FIXME: see comment in ws_llc_mngt_ind
    if (!ws_wp_nested_netname_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, &ie_netname)) {
        TRACE(TR_DROP, "drop %-9s: missing NETNAME-IE", tr_ws_frame(frame_type));
        return false;
    }
    return ws_ie_validate_netname(ws_info, &ie_netname);
}

static void ws_mngt_ie_pom_handle(struct ws_info *ws_info,
                                  const struct mcps_data_ind *data,
                                  const struct mcps_data_rx_ie_list *ie_ext)
{
    struct ws_neigh *ws_neigh = ws_neigh_get(&ws_info->neighbor_storage, data->SrcAddr);
    struct ws_pom_ie ie_pom;

    if (!ws_neigh)
        return;
    if (!ws_wp_nested_pom_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, &ie_pom))
        return;
    ws_neigh->pom_ie = ie_pom;
}

static struct ws_neigh *ws_mngt_neigh_fetch(struct ws_info *ws_info, const uint8_t *mac64, uint8_t role)
{
    struct ws_neigh *ws_neigh = ws_neigh_get(&ws_info->neighbor_storage, mac64);

    if (ws_neigh)
        return ws_neigh;
    return ws_neigh_add(&ws_info->neighbor_storage, mac64, role, ws_info->tx_power_dbm,
                        ws_info->key_index_mask);
}

void ws_mngt_pa_analyze(struct ws_info *ws_info,
                        const struct mcps_data_ind *data,
                        const struct mcps_data_rx_ie_list *ie_ext)
{
    struct ws_neigh *ws_neigh;
    struct ws_pan_ie ie_pan;
    struct ws_utt_ie ie_utt;
    struct ws_us_ie ie_us;

    if (!ws_mngt_ie_utt_validate(ie_ext, &ie_utt, WS_FT_PA))
        return;
    if (!ws_mngt_ie_us_validate(ws_info, ie_ext, &ie_us, WS_FT_PA))
        return;
    // FIXME: see comment in ws_llc_mngt_ind
    if (!ws_wp_nested_pan_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, &ie_pan)) {
        TRACE(TR_DROP, "drop %-9s: missing PAN-IE", tr_ws_frame(WS_FT_PA));
        return;
    }
    if (!ws_mngt_ie_netname_validate(ws_info, ie_ext, WS_FT_PA))
        return;

    if (data->SrcPANId != ws_info->pan_information.pan_id) {
        TRACE(TR_DROP, "drop %-9s: PAN ID mismatch", tr_ws_frame(WS_FT_PA));
        return;
    }

    ws_mngt_ie_pom_handle(ws_info, data, ie_ext);
    if (!ie_pan.use_parent_bs_ie)
        TRACE(TR_IGNORE, "ignore %-9s: unsupported local BS-IE", "15.4");
    if (!ie_pan.routing_method)
        TRACE(TR_IGNORE, "ignore %-9s: unsupported routing method", "15.4");
    if (ie_pan.fan_tps_version > WS_FAN_VERSION_1_0 && ie_pan.lfn_window_style)
        TRACE(TR_IGNORE, "ignore %-9s: unsupported LFN window style", "15.4");
    // Border router routing cost is 0, so "Routing Cost the same or worse" is
    // always true
    if (ie_pan.routing_cost != 0xFFFF)
        trickle_legacy_consistent(&ws_info->mngt.trickle_pa);
    ws_neigh = ws_mngt_neigh_fetch(ws_info, data->SrcAddr, WS_NR_ROLE_ROUTER);
    if (!ws_neigh)
        return;
    ws_neigh_ut_update(&ws_neigh->fhss_data_unsecured, ie_utt.ufsi, data->hif.timestamp_us, data->SrcAddr);
    ws_neigh_us_update(&ws_info->fhss_config, &ws_neigh->fhss_data_unsecured, &ie_us.chan_plan,
                       ie_us.dwell_interval);
}

void ws_mngt_pas_analyze(struct ws_info *ws_info,
                         const struct mcps_data_ind *data,
                         const struct mcps_data_rx_ie_list *ie_ext)
{
    struct ws_neigh *ws_neigh;
    struct ws_utt_ie ie_utt;
    struct ws_us_ie ie_us;

    if (!ws_mngt_ie_utt_validate(ie_ext, &ie_utt, WS_FT_PAS))
        return;
    if (!ws_mngt_ie_us_validate(ws_info, ie_ext, &ie_us, WS_FT_PAS))
        return;
    if (!ws_mngt_ie_netname_validate(ws_info, ie_ext, WS_FT_PAS))
        return;

    ws_mngt_ie_pom_handle(ws_info, data, ie_ext);
    trickle_legacy_inconsistent(&ws_info->mngt.trickle_pa,
                               &ws_info->mngt.trickle_params);
    ws_neigh = ws_mngt_neigh_fetch(ws_info, data->SrcAddr, WS_NR_ROLE_ROUTER);
    if (!ws_neigh)
        return;
    ws_neigh_ut_update(&ws_neigh->fhss_data_unsecured, ie_utt.ufsi, data->hif.timestamp_us, data->SrcAddr);
    ws_neigh_us_update(&ws_info->fhss_config, &ws_neigh->fhss_data_unsecured, &ie_us.chan_plan,
                       ie_us.dwell_interval);
}

void ws_mngt_pc_analyze(struct ws_info *ws_info,
                        const struct mcps_data_ind *data,
                        const struct mcps_data_rx_ie_list *ie_ext)
{
    struct ws_neigh *ws_neigh;
    uint16_t ws_pan_version;
    struct ws_utt_ie ie_utt;
    struct ws_bt_ie ie_bt;
    struct ws_us_ie ie_us;
    struct ws_bs_ie ie_bs;

    if (data->Key.SecurityLevel != IEEE802154_SEC_LEVEL_ENC_MIC64) {
        TRACE(TR_DROP, "drop %-9s: unencrypted frame", tr_ws_frame(WS_FT_PC));
        return;
    }

    if (!ws_mngt_ie_utt_validate(ie_ext, &ie_utt, WS_FT_PC))
        return;
    if (!ws_wh_bt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_bt)) {
        TRACE(TR_DROP, "drop %-9s: missing BT-IE", tr_ws_frame(WS_FT_PC));
        return;
    }
    if (!ws_mngt_ie_us_validate(ws_info, ie_ext, &ie_us, WS_FT_PC))
        return;
    // FIXME: see comment in ws_llc_mngt_ind
    if (!ws_wp_nested_bs_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, &ie_bs)) {
        TRACE(TR_DROP, "drop %-9s: missing BS-IE", tr_ws_frame(WS_FT_PC));
        return;
    }
    // FIXME: see comment in ws_llc_mngt_ind
    if (!ws_wp_nested_panver_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, &ws_pan_version)) {
        TRACE(TR_DROP, "drop %-9s: missing PANVER-IE", tr_ws_frame(WS_FT_PC));
        return;
    }

    if (data->SrcPANId != ws_info->pan_information.pan_id) {
        TRACE(TR_DROP, "drop %-9s: PAN ID mismatch", tr_ws_frame(WS_FT_PC));
        return;
    }

    if (ws_info->pan_information.pan_version == ws_pan_version)
        trickle_legacy_consistent(&ws_info->mngt.trickle_pc);
    else
        trickle_legacy_inconsistent(&ws_info->mngt.trickle_pc,
                                   &ws_info->mngt.trickle_params);

    ws_neigh = ws_mngt_neigh_fetch(ws_info, data->SrcAddr, WS_NR_ROLE_ROUTER);
    if (!ws_neigh)
        return;
    ws_neigh_ut_update(&ws_neigh->fhss_data, ie_utt.ufsi, data->hif.timestamp_us, data->SrcAddr);
    ws_neigh_ut_update(&ws_neigh->fhss_data_unsecured, ie_utt.ufsi, data->hif.timestamp_us, data->SrcAddr);
    ws_neigh_us_update(&ws_info->fhss_config, &ws_neigh->fhss_data, &ie_us.chan_plan,ie_us.dwell_interval);
    ws_neigh_us_update(&ws_info->fhss_config, &ws_neigh->fhss_data_unsecured, &ie_us.chan_plan,ie_us.dwell_interval);
}

void ws_mngt_pcs_analyze(struct ws_info *ws_info,
                         const struct mcps_data_ind *data,
                         const struct mcps_data_rx_ie_list *ie_ext)
{
    struct ws_neigh *ws_neigh;
    struct ws_utt_ie ie_utt;
    struct ws_us_ie ie_us;

    if (!ws_mngt_ie_utt_validate(ie_ext, &ie_utt, WS_FT_PCS))
        return;
    if (!ws_mngt_ie_us_validate(ws_info, ie_ext, &ie_us, WS_FT_PCS))
        return;
    if (!ws_mngt_ie_netname_validate(ws_info, ie_ext, WS_FT_PCS))
        return;

    if (data->SrcPANId != ws_info->pan_information.pan_id) {
        TRACE(TR_DROP, "drop %-9s: PAN ID mismatch", tr_ws_frame(WS_FT_PCS));
        return;
    }

    trickle_legacy_inconsistent(&ws_info->mngt.trickle_pc,
                               &ws_info->mngt.trickle_params);

    ws_neigh = ws_mngt_neigh_fetch(ws_info, data->SrcAddr, WS_NR_ROLE_ROUTER);
    if (!ws_neigh)
        return;
    ws_neigh_ut_update(&ws_neigh->fhss_data_unsecured, ie_utt.ufsi, data->hif.timestamp_us, data->SrcAddr);
    ws_neigh_us_update(&ws_info->fhss_config, &ws_neigh->fhss_data_unsecured, &ie_us.chan_plan,
                       ie_us.dwell_interval);
}

void ws_mngt_lpa_send(struct ws_info *ws_info, const uint8_t dst[8])
{
    struct ws_llc_mngt_req req = {
        .frame_type = WS_FT_LPA,
        .wh_ies.utt     = true,
        .wh_ies.bt      = true,
        .wh_ies.lbt     = true,
        .wh_ies.nr      = true,
        .wh_ies.flus    = true,
        .wh_ies.lbs     = true,
        .wh_ies.panid   = true,
        .wp_ies.bs      = true,
        .wp_ies.pan     = &(struct ws_pan_ie) {
            // PAN size is filled later
            .routing_cost     = 0, // Border router routing cost is 0
            // Remaining field are ignored
            // Reserved
            .fan_tps_version  = ws_info->pan_information.version,
        },
        .wp_ies.netname = true,
        .wp_ies.lcp     = true,
        .wp_ies.jm      = memzcmp(ws_info->pan_information.jm.metrics, sizeof(ws_info->pan_information.jm.metrics)),
    };

    ws_llc_mngt_lfn_request(&req, dst);
}

static void ws_mngt_lpa_schedule(struct ws_mngt *mngt, struct ws_lnd_ie *ie_lnd, const uint8_t eui64[8])
{
    const uint16_t slot = rand_get_random_in_range(0, ie_lnd->discovery_slots);
    const int timeout = slot * ie_lnd->discovery_slot_time + ie_lnd->response_delay;

    // FIXME: The LPA slot should be chosen by the RCP. UART transmission
    // delays likely implies that the slot is missed and one of the later
    // slots is used instead (if any).
    memcpy(mngt->lpa_dst, eui64, 8);
    // Start timer
    g_timers[WS_TIMER_LPA].timeout = timeout / WS_TIMER_GLOBAL_PERIOD_MS;
}

void ws_mngt_lpas_analyze(struct ws_info *ws_info,
                          const struct mcps_data_ind *data,
                          const struct mcps_data_rx_ie_list *ie_ext)
{
    int fixed_channel = ws_chan_mask_get_fixed(ws_info->fhss_config.uc_chan_mask);
    uint8_t chan_func = (fixed_channel < 0) ? WS_CHAN_FUNC_DH1CF : WS_CHAN_FUNC_FIXED;
    struct ws_neigh *ws_neigh;
    struct ws_lutt_ie ie_lutt;
    struct ws_lus_ie ie_lus;
    struct ws_lnd_ie ie_lnd;
    struct ws_lcp_ie ie_lcp;
    struct ws_nr_ie ie_nr;
    bool add_neighbor;

    if (g_timers[WS_TIMER_LPA].timeout) {
        TRACE(TR_DROP, "drop %-9s: LPA already queued for %s",
              tr_ws_frame(WS_FT_LPAS), tr_eui64(ws_info->mngt.lpa_dst));
        return;
    }

    if (!ws_wh_lutt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_lutt)) {
        TRACE(TR_DROP, "drop %-9s: missing LUTT-IE", tr_ws_frame(WS_FT_LPAS));
        return;
    }
    BUG_ON(ie_lutt.message_type != WS_FT_LPAS);
    if (!ws_wh_lus_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_lus)) {
        TRACE(TR_DROP, "drop %-9s: missing LUS-IE", tr_ws_frame(WS_FT_LPAS));
        return;
    }
    if (!ws_wh_nr_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_nr)) {
        TRACE(TR_DROP, "drop %-9s: missing NR-IE", tr_ws_frame(WS_FT_LPAS));
        return;
    }
    if (!ws_wh_lnd_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_lnd)) {
        TRACE(TR_DROP, "drop %-9s: missing LND-IE", tr_ws_frame(WS_FT_LPAS));
        return;
    }
    // FIXME: see comment in ws_llc_mngt_ind
    if (!ws_wp_nested_lcp_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, ie_lus.channel_plan_tag, &ie_lcp)) {
        TRACE(TR_DROP, "drop %-9s: missing LCP-IE required by LUS-IE", tr_ws_frame(WS_FT_LPAS));
        return;
    }
    if (ie_lcp.chan_plan.channel_function != chan_func) {
        TRACE(TR_DROP, "drop %-9s: LUS-IE/LCP-IE channel function mismatch", tr_ws_frame(WS_FT_LPAS));
        return;
    }
    if (!ws_ie_validate_lcp(ws_info, &ie_lcp))
        return;
    if (!ws_mngt_ie_netname_validate(ws_info, ie_ext, WS_FT_LPAS))
        return;

    // [...] an FFN MUST ignore the LPAS if [...]
    // The receive signal-level-above-sensitivity for the LPAS falls below the
    // LND-IE Response Threshold.
    if (data->hif.rx_power_dbm < (DEVICE_MIN_SENS + ie_lnd.response_threshold)) {
        TRACE(TR_DROP, "drop %-9s: RSL below LND-IE response threshold", tr_ws_frame(WS_FT_LPAS));
        return;
    }

    add_neighbor = false;
    ws_neigh = ws_neigh_get(&ws_info->neighbor_storage, data->SrcAddr);

    if (!ws_neigh) {
        add_neighbor = true;
    } else if (ws_neigh->node_role != WS_NR_ROLE_LFN) {
        WARN("node changed role");
        ws_neigh_del(&ws_info->neighbor_storage, ws_neigh->mac64);
        add_neighbor = true;
    }
    if (add_neighbor) {
        ws_neigh = ws_neigh_add(&ws_info->neighbor_storage, data->SrcAddr, WS_NR_ROLE_LFN,
                                ws_info->tx_power_dbm, ws_info->key_index_mask);
        if (!ws_neigh) {
            TRACE(TR_DROP, "drop %-9s: could not allocate neighbor %s", tr_ws_frame(WS_FT_LPAS), tr_eui64(data->SrcAddr));
            return;
        }
    }

    ws_neigh_lut_update(&ws_neigh->fhss_data_unsecured, ie_lutt.slot_number, ie_lutt.interval_offset,
                                 data->hif.timestamp_us);
    ws_neigh->lto_info.offset_adjusted = ws_neigh_lus_update(&ws_info->fhss_config, &ws_neigh->fhss_data_unsecured, &ie_lcp.chan_plan,
                                                             ie_lus.listen_interval, &ws_neigh->lto_info);
    ws_neigh_lnd_update(&ws_neigh->fhss_data_unsecured, &ie_lnd, data->hif.timestamp_us);

    ws_neigh_nr_update(ws_neigh, &ie_nr);

    ws_mngt_lpa_schedule(&ws_info->mngt, &ie_lnd, data->SrcAddr);
}

static void ws_mngt_lpc_send(struct ws_info *ws_info, const uint8_t dst[8])
{
    struct ws_llc_mngt_req req = {
        .frame_type = WS_FT_LPC,
        .wh_ies.utt      = true,
        .wh_ies.lbt      = true,
        .wp_ies.lfnver   = true,
        .wp_ies.lgtkhash = true,
        .security.SecurityLevel = IEEE802154_SEC_LEVEL_ENC_MIC64,
        .security.KeyIndex      = ws_info->lfn_gtk_index,
    };

    ws_llc_mngt_lfn_request(&req, dst);
}

void ws_mngt_lpc_pae_cb(struct ws_info *ws_info)
{
    if (ws_neigh_lfn_count(&ws_info->neighbor_storage))
        ws_mngt_lpc_send(ws_info, NULL);
}

void ws_mngt_lpcs_analyze(struct ws_info *ws_info,
                          const struct mcps_data_ind *data,
                          const struct mcps_data_rx_ie_list *ie_ext)
{
    struct ws_neigh *ws_neigh;
    struct ws_lutt_ie ie_lutt;
    struct ws_lus_ie ie_lus;
    struct ws_lcp_ie ie_lcp;
    bool has_lus, has_lcp;

    if (!ws_wh_lutt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_lutt)) {
        TRACE(TR_DROP, "drop %-9s: missing LUTT-IE", tr_ws_frame(WS_FT_LPCS));
        return;
    }
    BUG_ON(ie_lutt.message_type != WS_FT_LPCS);
    if (!ws_mngt_ie_netname_validate(ws_info, ie_ext, WS_FT_LPCS))
        return;

    // TODO: Factorize this code with EAPOL and MPX LFN indication
    has_lus = ws_wh_lus_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_lus);
    has_lcp = false;
    if (has_lus && ie_lus.channel_plan_tag != WS_CHAN_PLAN_TAG_CURRENT) {
        has_lcp = ws_wp_nested_lcp_read(ie_ext->headerIeList, ie_ext->headerIeListLength,
                                        ie_lus.channel_plan_tag, &ie_lcp);
        if (!has_lcp) {
            TRACE(TR_DROP, "drop %-9s: missing LCP-IE required by LUS-IE", tr_ws_frame(WS_FT_LPCS));
            return;
        }
        if (!ws_ie_validate_lcp(ws_info, &ie_lcp))
            return;
    }

    ws_neigh = ws_neigh_get(&ws_info->neighbor_storage, data->SrcAddr);
    if (!ws_neigh) {
        TRACE(TR_DROP, "drop %-9s: unknown neighbor %s", tr_ws_frame(WS_FT_LPCS), tr_eui64(data->SrcAddr));
        return;
    }

    if (has_lus) {
        ws_neigh_lut_update(&ws_neigh->fhss_data_unsecured, ie_lutt.slot_number, ie_lutt.interval_offset,
                            data->hif.timestamp_us);
        ws_neigh->lto_info.offset_adjusted = ws_neigh_lus_update(&ws_info->fhss_config, &ws_neigh->fhss_data_unsecured,
                                                                 has_lcp ? &ie_lcp.chan_plan : NULL,
                                                                 ie_lus.listen_interval, &ws_neigh->lto_info);
    }

    ws_mngt_lpc_send(ws_info, data->SrcAddr);
}

void ws_mngt_ind(struct ws_info *ws_info, const struct mcps_data_ind *data,
                 const struct mcps_data_rx_ie_list *ie_ext, uint8_t message_type)
{
    if (data->SrcAddrMode != IEEE802154_ADDR_MODE_64_BIT) {
        // Not from long address
        return;
    }
    //Handle Message's
    switch (message_type) {
        case WS_FT_PA:
            ws_mngt_pa_analyze(ws_info, data, ie_ext);
            break;
        case WS_FT_PAS:
            ws_mngt_pas_analyze(ws_info, data, ie_ext);
            break;
        case WS_FT_PC:
            ws_mngt_pc_analyze(ws_info, data, ie_ext);
            break;
        case WS_FT_PCS:
            ws_mngt_pcs_analyze(ws_info, data, ie_ext);
            break;
        case WS_FT_LPAS:
            ws_mngt_lpas_analyze(ws_info, data, ie_ext);
            break;
        case WS_FT_LPCS:
            ws_mngt_lpcs_analyze(ws_info, data, ie_ext);
            break;
        case WS_FT_LPA:
        case WS_FT_LPC:
            WARN("LFN messages are not yet supported");
        default:
            // Unknown message do not process
            break;
    }
}

void ws_mngt_cnf(struct ws_info *ws_info, uint8_t asynch_message)
{
    if (asynch_message == WS_FT_PA)
        ws_info->mngt.pan_advert_running = false;
    else if (asynch_message == WS_FT_PC)
        ws_info->mngt.pan_config_running = false;
}

void ws_mngt_pa_send(struct ws_info *ws_info)
{
    const struct ws_phy_config *schedule = &ws_info->phy_config;
    struct ws_llc_mngt_req req = {
        .frame_type = WS_FT_PA,
        .wh_ies.utt     = true,
        .wp_ies.us      = true,
        .wp_ies.pan     = &(struct ws_pan_ie) {
            // PAN size is filled later
            .routing_cost     = 0, // Border router routing cost is 0
            // Remaining field are ignored
            // Reserved
            .fan_tps_version  = ws_info->pan_information.version,
        },
        .wp_ies.netname = true,
        .wp_ies.pom     = schedule->phy_op_modes[0] && schedule->phy_op_modes[1],
        .wp_ies.jm      = memzcmp(ws_info->pan_information.jm.metrics, sizeof(ws_info->pan_information.jm.metrics)),
    };

    ws_info->pan_information.routing_cost = 0;

    ws_llc_asynch_request(ws_info, &req);
}

void ws_mngt_pc_send(struct ws_info *ws_info)
{
    struct ws_llc_mngt_req req = {
        .frame_type = WS_FT_PC,
        .wh_ies.utt      = true,
        .wh_ies.bt       = true,
        .wh_ies.lbc      = ws_info->enable_lfn,
        .wp_ies.us       = true,
        .wp_ies.bs       = true,
        .wp_ies.panver   = true,
        .wp_ies.gtkhash  = true,
        .wp_ies.lgtkhash = ws_info->enable_lfn,
        .wp_ies.lfnver   = ws_info->enable_lfn,
        .security.SecurityLevel = IEEE802154_SEC_LEVEL_ENC_MIC64,
        .security.KeyIndex = ws_info->ffn_gtk_index
    };

    ws_llc_asynch_request(ws_info, &req);
}

void ws_mngt_async_trickle_start(struct ws_info *ws_info)
{
    trickle_legacy_start(&ws_info->mngt.trickle_pa, "ADV", &ws_info->mngt.trickle_params);
    trickle_legacy_start(&ws_info->mngt.trickle_pc, "CFG", &ws_info->mngt.trickle_params);
}

void ws_mngt_async_trickle_stop(struct ws_info *ws_info)
{
    trickle_legacy_stop(&ws_info->mngt.trickle_pa);
    trickle_legacy_stop(&ws_info->mngt.trickle_pc);
}

void ws_mngt_async_trickle_reset_pc(struct ws_info *ws_info)
{
    trickle_legacy_inconsistent(&ws_info->mngt.trickle_pc, &ws_info->mngt.trickle_params);
}

void ws_mngt_async_trickle_timer_cb(struct ws_info *ws_info, uint16_t ticks)
{
    if (trickle_legacy_tick(&ws_info->mngt.trickle_pa, &ws_info->mngt.trickle_params, ticks))
        ws_mngt_pa_send(ws_info);
    if (trickle_legacy_tick(&ws_info->mngt.trickle_pc, &ws_info->mngt.trickle_params, ticks))
        ws_mngt_pc_send(ws_info);
}

void ws_mngt_lts_send(struct ws_info *ws_info)
{
    struct ws_llc_mngt_req req = {
        .frame_type = WS_FT_LTS,
        .wh_ies.utt    = true,
        .wh_ies.bt     = true,
        .wh_ies.lbt    = true,
        .wp_ies.lfnver = true,
        .security.SecurityLevel = IEEE802154_SEC_LEVEL_ENC_MIC64,
        .security.KeyIndex      = ws_info->lfn_gtk_index,
    };

    ws_llc_mngt_lfn_request(&req, NULL);
}

void ws_mngt_pan_version_increase(struct ws_info *ws_info)
{
    INFO("PAN version number update");
    // Version number is not periodically increased forcing nodes to check Border router availability using DAO
    ws_info->pan_information.pan_version++;
    // Inconsistent for border router to make information distribute faster
    ws_mngt_async_trickle_reset_pc(ws_info);
    ws_pan_info_storage_write(ws_info->fhss_config.bsi, ws_info->pan_information.pan_id,
                              ws_info->pan_information.pan_version, ws_info->pan_information.lfn_version,
                              ws_info->network_name);
}

void ws_mngt_lfn_version_increase(struct ws_info *ws_info)
{
    INFO("LFN version number update");
    // ws_mngt_pan_version_increase() will reset the PC trickle and update the
    // storage
    ws_info->pan_information.lfn_version++;

    //   Wi-SUN FAN 1.1v06 6.3.4.6.3 FFN Discovery / Join
    // A Border Router MUST increment PAN Version (PANVER-IE) [...] when [...]
    // the following occurs:
    // d. A change in LFN Version.
    ws_mngt_pan_version_increase(ws_info);
}
