/*
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
#include "common/log.h"
#include "common/named_values.h"
#include "common/rand.h"
#include "common/trickle.h"
#include "common/specs/ieee802154.h"
#include "common/specs/ws.h"
#include "app_wsbrd/rcp_api_legacy.h"

#include "stack/source/core/timers.h"
#include "stack/source/6lowpan/mac/mac_helper.h"
#include "stack/source/6lowpan/ws/ws_bbr_api.h"
#include "stack/source/6lowpan/ws/ws_bootstrap.h"
#include "stack/source/6lowpan/ws/ws_cfg_settings.h"
#include "stack/source/6lowpan/ws/ws_common.h"
#include "stack/source/6lowpan/ws/ws_mngt.h"
#include "stack/source/6lowpan/ws/ws_ie_lib.h"
#include "stack/source/6lowpan/ws/ws_ie_validation.h"
#include "stack/source/6lowpan/ws/ws_llc.h"
#include "stack/source/nwk_interface/protocol.h"

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

static bool ws_mngt_ie_us_validate(struct net_if *net_if,
                                   const struct mcps_data_rx_ie_list *ie_ext,
                                   struct ws_us_ie *ie_us,
                                   uint8_t frame_type)
{
    // FIXME: see comment in ws_llc_mngt_ind
    if (!ws_wp_nested_us_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, ie_us)) {
        TRACE(TR_DROP, "drop %-9s: missing US-IE", tr_ws_frame(frame_type));
        return false;
    }
    return ws_ie_validate_us(&net_if->ws_info, ie_us);
}

static bool ws_mngt_ie_netname_validate(struct net_if *net_if,
                                        const struct mcps_data_rx_ie_list *ie_ext,
                                        uint8_t frame_type)
{
    ws_wp_netname_t ie_netname;

    // FIXME: see comment in ws_llc_mngt_ind
    if (!ws_wp_nested_netname_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, &ie_netname)) {
        TRACE(TR_DROP, "drop %-9s: missing NETNAME-IE", tr_ws_frame(frame_type));
        return false;
    }
    return ws_ie_validate_netname(&net_if->ws_info, &ie_netname);
}

static void ws_mngt_ie_pom_handle(struct net_if *net_if,
                                  const struct mcps_data_ind *data,
                                  const struct mcps_data_rx_ie_list *ie_ext)
{
    struct ws_neigh *ws_neigh = ws_neigh_get(&net_if->ws_info.neighbor_storage, data->SrcAddr);
    ws_pom_ie_t ie_pom;

    if (!ws_neigh)
        return;
    if (!ws_wp_nested_pom_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, &ie_pom))
        return;
    ws_neigh->pom_ie = ie_pom;
}

void ws_mngt_pa_analyze(struct net_if *net_if,
                        const struct mcps_data_ind *data,
                        const struct mcps_data_rx_ie_list *ie_ext)
{
    ws_pan_information_t pan_information;
    ws_utt_ie_t ie_utt;
    ws_us_ie_t ie_us;

    if (!ws_mngt_ie_utt_validate(ie_ext, &ie_utt, WS_FT_PA))
        return;
    if (!ws_mngt_ie_us_validate(net_if, ie_ext, &ie_us, WS_FT_PA))
        return;
    // FIXME: see comment in ws_llc_mngt_ind
    if (!ws_wp_nested_pan_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, &pan_information)) {
        TRACE(TR_DROP, "drop %-9s: missing PAN-IE", tr_ws_frame(WS_FT_PA));
        return;
    }
    if (!ws_mngt_ie_netname_validate(net_if, ie_ext, WS_FT_PA))
        return;

    if (data->SrcPANId != net_if->ws_info.pan_information.pan_id) {
        TRACE(TR_DROP, "drop %-9s: PAN ID mismatch", tr_ws_frame(WS_FT_PA));
        return;
    }

    ws_mngt_ie_pom_handle(net_if, data, ie_ext);
    // Border router routing cost is 0, so "Routing Cost the same or worse" is
    // always true
    if (pan_information.routing_cost != 0xFFFF)
        trickle_consistent_heard(&net_if->ws_info.mngt.trickle_pa);
}

void ws_mngt_pas_analyze(struct net_if *net_if,
                         const struct mcps_data_ind *data,
                         const struct mcps_data_rx_ie_list *ie_ext)
{
    ws_utt_ie_t ie_utt;
    ws_us_ie_t ie_us;

    if (!ws_mngt_ie_utt_validate(ie_ext, &ie_utt, WS_FT_PAS))
        return;
    if (!ws_mngt_ie_us_validate(net_if, ie_ext, &ie_us, WS_FT_PAS))
        return;
    if (!ws_mngt_ie_netname_validate(net_if, ie_ext, WS_FT_PAS))
        return;

    ws_mngt_ie_pom_handle(net_if, data, ie_ext);
    trickle_inconsistent_heard(&net_if->ws_info.mngt.trickle_pa,
                               &net_if->ws_info.mngt.trickle_params);
}

void ws_mngt_pc_analyze(struct net_if *net_if,
                        const struct mcps_data_ind *data,
                        const struct mcps_data_rx_ie_list *ie_ext)
{
    struct ws_neigh *ws_neigh;
    uint16_t ws_pan_version;
    ws_utt_ie_t ie_utt;
    ws_bt_ie_t ie_bt;
    ws_us_ie_t ie_us;
    ws_bs_ie_t ie_bs;

    if (data->Key.SecurityLevel != SEC_ENC_MIC64) {
        TRACE(TR_DROP, "drop %-9s: unencrypted frame", tr_ws_frame(WS_FT_PC));
        return;
    }

    if (!ws_mngt_ie_utt_validate(ie_ext, &ie_utt, WS_FT_PC))
        return;
    if (!ws_wh_bt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_bt)) {
        TRACE(TR_DROP, "drop %-9s: missing BT-IE", tr_ws_frame(WS_FT_PC));
        return;
    }
    if (!ws_mngt_ie_us_validate(net_if, ie_ext, &ie_us, WS_FT_PC))
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

    if (data->SrcPANId != net_if->ws_info.pan_information.pan_id) {
        TRACE(TR_DROP, "drop %-9s: PAN ID mismatch", tr_ws_frame(WS_FT_PC));
        return;
    }

    if (net_if->ws_info.pan_information.pan_version == ws_pan_version)
        trickle_consistent_heard(&net_if->ws_info.mngt.trickle_pc);
    else
        trickle_inconsistent_heard(&net_if->ws_info.mngt.trickle_pc,
                                   &net_if->ws_info.mngt.trickle_params);

    ws_neigh = ws_neigh_get(&net_if->ws_info.neighbor_storage, data->SrcAddr);
    if (!ws_neigh && ipv6_neighbour_lookup_gua_by_eui64(&net_if->ipv6_neighbour_cache, data->SrcAddr))
        ws_neigh = ws_bootstrap_neighbor_add(net_if, data->SrcAddr, WS_NR_ROLE_ROUTER);
    if (!ws_neigh)
        return;
    ws_neigh_ut_update(ws_neigh, ie_utt.ufsi, data->timestamp, data->SrcAddr);
    ws_neigh_us_update(net_if, ws_neigh, &ie_us.chan_plan,ie_us.dwell_interval, data->SrcAddr);
}

void ws_mngt_pcs_analyze(struct net_if *net_if,
                         const struct mcps_data_ind *data,
                         const struct mcps_data_rx_ie_list *ie_ext)
{
    struct ws_neigh *ws_neigh;
    ws_utt_ie_t ie_utt;
    ws_us_ie_t ie_us;

    if (!ws_mngt_ie_utt_validate(ie_ext, &ie_utt, WS_FT_PCS))
        return;
    if (!ws_mngt_ie_us_validate(net_if, ie_ext, &ie_us, WS_FT_PCS))
        return;
    if (!ws_mngt_ie_netname_validate(net_if, ie_ext, WS_FT_PCS))
        return;

    if (data->SrcPANId != net_if->ws_info.pan_information.pan_id) {
        TRACE(TR_DROP, "drop %-9s: PAN ID mismatch", tr_ws_frame(WS_FT_PCS));
        return;
    }

    trickle_inconsistent_heard(&net_if->ws_info.mngt.trickle_pc,
                               &net_if->ws_info.mngt.trickle_params);

    ws_neigh = ws_neigh_get(&net_if->ws_info.neighbor_storage, data->SrcAddr);
    if (!ws_neigh && ipv6_neighbour_lookup_gua_by_eui64(&net_if->ipv6_neighbour_cache, data->SrcAddr))
        ws_neigh = ws_bootstrap_neighbor_add(net_if, data->SrcAddr, WS_NR_ROLE_ROUTER);
    if (!ws_neigh)
        return;
    ws_neigh_ut_update(ws_neigh, ie_utt.ufsi, data->timestamp, data->SrcAddr);
    ws_neigh_us_update(net_if, ws_neigh, &ie_us.chan_plan, ie_us.dwell_interval, data->SrcAddr);
}

static void ws_mngt_lpa_send(struct net_if *net_if, const uint8_t dst[8])
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
        .wp_ies.pan     = true,
        .wp_ies.netname = true,
        .wp_ies.lcp     = true,
    };

    net_if->ws_info.pan_information.pan_size = ws_bbr_pan_size(net_if);
    // TODO: JM-IE
    ws_llc_mngt_lfn_request(net_if, &req, dst, MAC_DATA_HIGH_PRIORITY);
}

void ws_mngt_lpa_timer_cb(int ticks)
{
    struct net_if *net_if = protocol_stack_interface_info_get();

    ws_mngt_lpa_send(net_if, net_if->ws_info.mngt.lpa_dst);
}

static void ws_mngt_lpa_schedule(struct net_if *net_if, struct ws_lnd_ie *ie_lnd, const uint8_t eui64[8])
{
    const uint16_t slot = rand_get_random_in_range(0, ie_lnd->discovery_slots);
    const int timeout = slot * ie_lnd->discovery_slot_time + ie_lnd->response_delay;

    // FIXME: The LPA slot should be chosen by the RCP. UART transmission
    // delays likely implies that the slot is missed and one of the later
    // slots is used instead (if any).
    memcpy(net_if->ws_info.mngt.lpa_dst, eui64, 8);
    // Start timer
    g_timers[WS_TIMER_LPA].timeout = timeout / WS_TIMER_GLOBAL_PERIOD_MS;
}

void ws_mngt_lpas_analyze(struct net_if *net_if,
                          const struct mcps_data_ind *data,
                          const struct mcps_data_rx_ie_list *ie_ext)
{
    struct ws_neigh *ws_neigh;
    struct ws_lutt_ie ie_lutt;
    struct ws_lus_ie ie_lus;
    struct ws_lnd_ie ie_lnd;
    struct ws_lcp_ie ie_lcp;
    struct ws_nr_ie ie_nr;
    bool add_neighbor;

    if (g_timers[WS_TIMER_LPA].timeout) {
        TRACE(TR_DROP, "drop %-9s: LPA already queued for %s",
              tr_ws_frame(WS_FT_LPAS), tr_eui64(net_if->ws_info.mngt.lpa_dst));
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
    if (ie_lcp.chan_plan.channel_function != net_if->ws_info.cfg->fhss.fhss_uc_channel_function) {
        TRACE(TR_DROP, "drop %-9s: LUS-IE/LCP-IE channel function mismatch", tr_ws_frame(WS_FT_LPAS));
        return;
    }
    if (!ws_ie_validate_lcp(&net_if->ws_info, &ie_lcp))
        return;
    if (!ws_mngt_ie_netname_validate(net_if, ie_ext, WS_FT_LPAS))
        return;

    // [...] an FFN MUST ignore the LPAS if [...]
    // The receive signal-level-above-sensitivity for the LPAS falls below the
    // LND-IE Response Threshold.
    if (data->signal_dbm < (DEVICE_MIN_SENS + ie_lnd.response_threshold)) {
        TRACE(TR_DROP, "drop %-9s: RSL below LND-IE response threshold", tr_ws_frame(WS_FT_LPAS));
        return;
    }

    add_neighbor = false;
    ws_neigh = ws_neigh_get(&net_if->ws_info.neighbor_storage, data->SrcAddr);

    if (!ws_neigh) {
        add_neighbor = true;
    } else if (ws_neigh->node_role != WS_NR_ROLE_LFN) {
        WARN("node changed role");
        ws_bootstrap_neighbor_del(ws_neigh->mac64);
        add_neighbor = true;
    }
    if (add_neighbor) {
        ws_neigh = ws_bootstrap_neighbor_add(net_if, data->SrcAddr, WS_NR_ROLE_LFN);
        if (!ws_neigh) {
            TRACE(TR_DROP, "drop %-9s: could not allocate neighbor %s", tr_ws_frame(WS_FT_LPAS), tr_eui64(data->SrcAddr));
            return;
        }
    }

    ws_neigh_lut_update(ws_neigh, ie_lutt.slot_number, ie_lutt.interval_offset,
                                 data->timestamp, data->SrcAddr);
    ws_neigh_lus_update(net_if, ws_neigh, &ie_lcp.chan_plan, ie_lus.listen_interval);
    ws_neigh_lnd_update(ws_neigh, &ie_lnd, data->timestamp);

    ws_neigh_nr_update(ws_neigh, &ie_nr);

    ws_mngt_lpa_schedule(net_if, &ie_lnd, data->SrcAddr);
}

static void ws_mngt_lpc_send(struct net_if *net_if, const uint8_t dst[8])
{
    struct ws_llc_mngt_req req = {
        .frame_type = WS_FT_LPC,
        .wh_ies.utt      = true,
        .wh_ies.lbt      = true,
        .wp_ies.lfnver   = true,
        .wp_ies.lgtkhash = true,
        .security.SecurityLevel = SEC_ENC_MIC64,
        .security.KeyIndex      = net_if->mac_parameters.mac_default_lfn_key_index,
    };

    ws_llc_mngt_lfn_request(net_if, &req, dst, MAC_DATA_MEDIUM_PRIORITY);
}

void ws_mngt_lpc_pae_cb(struct net_if *net_if)
{
    if (ws_neigh_lfn_count(&net_if->ws_info.neighbor_storage))
        ws_mngt_lpc_send(net_if, NULL);
}

void ws_mngt_lpcs_analyze(struct net_if *net_if,
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
    if (!ws_mngt_ie_netname_validate(net_if, ie_ext, WS_FT_LPCS))
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
        if (!ws_ie_validate_lcp(&net_if->ws_info, &ie_lcp))
            return;
    }

    ws_neigh = ws_neigh_get(&net_if->ws_info.neighbor_storage, data->SrcAddr);
    if (!ws_neigh) {
        TRACE(TR_DROP, "drop %-9s: unknown neighbor %s", tr_ws_frame(WS_FT_LPCS), tr_eui64(data->SrcAddr));
        return;
    }

    ws_neigh_lut_update(ws_neigh, ie_lutt.slot_number, ie_lutt.interval_offset,
                                 data->timestamp, data->SrcAddr);
    if (has_lus)
        ws_neigh_lus_update(net_if, ws_neigh,
                                     has_lcp ? &ie_lcp.chan_plan : NULL,
                                     ie_lus.listen_interval);

    ws_mngt_lpc_send(net_if, data->SrcAddr);
}

void ws_mngt_ind(struct net_if *cur, const struct mcps_data_ind *data,
                 const struct mcps_data_rx_ie_list *ie_ext, uint8_t message_type)
{
    if (data->SrcAddrMode != MAC_ADDR_MODE_64_BIT) {
        // Not from long address
        return;
    }
    //Handle Message's
    switch (message_type) {
        case WS_FT_PA:
            ws_mngt_pa_analyze(cur, data, ie_ext);
            break;
        case WS_FT_PAS:
            ws_mngt_pas_analyze(cur, data, ie_ext);
            break;
        case WS_FT_PC:
            ws_mngt_pc_analyze(cur, data, ie_ext);
            break;
        case WS_FT_PCS:
            ws_mngt_pcs_analyze(cur, data, ie_ext);
            break;
        case WS_FT_LPAS:
            ws_mngt_lpas_analyze(cur, data, ie_ext);
            break;
        case WS_FT_LPCS:
            ws_mngt_lpcs_analyze(cur, data, ie_ext);
            break;
        case WS_FT_LPA:
        case WS_FT_LPC:
            WARN("LFN messages are not yet supported");
        default:
            // Unknown message do not process
            break;
    }
}

void ws_mngt_cnf(struct net_if *interface, uint8_t asynch_message)
{
    if (asynch_message == WS_FT_PA)
        interface->pan_advert_running = false;
    else if (asynch_message == WS_FT_PC)
        interface->pan_config_running = false;
    if (asynch_message == WS_FT_PC && interface->ws_info.pending_key_index_info.state == PENDING_KEY_INDEX_ACTIVATE) {
        interface->ws_info.pending_key_index_info.state = NO_PENDING_PROCESS;
        /* Deprecated: Unused by the RCP. */
        interface->mac_parameters.mac_default_ffn_key_index = interface->ws_info.pending_key_index_info.index + 1;
    }
}

void ws_mngt_pa_send(struct net_if *cur)
{
    const struct ws_hopping_schedule *schedule = &cur->ws_info.hopping_schedule;
    struct ws_llc_mngt_req req = {
        .frame_type = WS_FT_PA,
        .wh_ies.utt     = true,
        .wp_ies.us      = true,
        .wp_ies.pan     = true,
        .wp_ies.netname = true,
        .wp_ies.pom     = schedule->phy_op_modes[0] && schedule->phy_op_modes[1],
        .wp_ies.jm      = cur->ws_info.pan_information.jm.mask,
    };
    uint8_t plf;

    // FIXME: we would like to compute these in ws_llc before including the
    // relevant IEs, but it is inconvenient since we are still supporting
    // FFNs for simulation.
    // Border routers write the NW size
    cur->ws_info.pan_information.pan_size = ws_bbr_pan_size(cur);
    if (cur->ws_info.pan_information.jm.mask & (1 << WS_JM_PLF)) {
        plf = ws_common_calc_plf(cur->ws_info.pan_information.pan_size,
                                    cur->ws_info.cfg->gen.network_size);
        if (plf != cur->ws_info.pan_information.jm.plf) {
            cur->ws_info.pan_information.jm.plf = plf;
            cur->ws_info.pan_information.jm.version++;
        }
    }
    cur->ws_info.pan_information.routing_cost = 0;

    ws_llc_asynch_request(cur, &req);
}

void ws_mngt_pc_send(struct net_if *cur)
{
    struct ws_llc_mngt_req req = {
        .frame_type = WS_FT_PC,
        .wh_ies.utt      = true,
        .wh_ies.bt       = true,
        .wh_ies.lbc      = cur->ws_info.pan_information.lfn_version_set,
        .wp_ies.us       = true,
        .wp_ies.bs       = true,
        .wp_ies.panver   = true,
        .wp_ies.gtkhash  = true,
        .wp_ies.lgtkhash = cur->ws_info.pan_information.lfn_version_set,
        .wp_ies.lfnver   = cur->ws_info.pan_information.lfn_version_set,
        .security.SecurityLevel = SEC_ENC_MIC64,
    };

    if (cur->ws_info.pending_key_index_info.state == PENDING_KEY_INDEX_ADVERTISMENT) {
        req.security.KeyIndex =  cur->ws_info.pending_key_index_info.index + 1;
        cur->ws_info.pending_key_index_info.state = PENDING_KEY_INDEX_ACTIVATE;
    } else {
        req.security.KeyIndex = cur->mac_parameters.mac_default_ffn_key_index;
    }

    ws_llc_asynch_request(cur, &req);
}

void ws_mngt_async_trickle_start(struct net_if *cur)
{
    trickle_start(&cur->ws_info.mngt.trickle_pa, "ADV", &cur->ws_info.mngt.trickle_params);
    trickle_start(&cur->ws_info.mngt.trickle_pc, "CFG", &cur->ws_info.mngt.trickle_params);
}

void ws_mngt_async_trickle_stop(struct net_if *cur)
{
    trickle_stop(&cur->ws_info.mngt.trickle_pa);
    trickle_stop(&cur->ws_info.mngt.trickle_pc);
}

void ws_mngt_async_trickle_reset_pc(struct net_if *cur)
{
    trickle_inconsistent_heard(&cur->ws_info.mngt.trickle_pc, &cur->ws_info.mngt.trickle_params);
}

void ws_mngt_async_trickle_timer_cb(struct net_if *cur, uint16_t ticks)
{
    if (trickle_timer(&cur->ws_info.mngt.trickle_pa, &cur->ws_info.mngt.trickle_params, ticks))
        ws_mngt_pa_send(cur);
    if (trickle_timer(&cur->ws_info.mngt.trickle_pc, &cur->ws_info.mngt.trickle_params, ticks))
        ws_mngt_pc_send(cur);
}

static void ws_mngt_lts_send(struct net_if *net_if)
{
    struct ws_llc_mngt_req req = {
        .frame_type = WS_FT_LTS,
        .wh_ies.utt    = true,
        .wh_ies.bt     = true,
        .wh_ies.lbt    = true,
        .wp_ies.lfnver = true,
        .security.SecurityLevel = SEC_ENC_MIC64,
        .security.KeyIndex      = net_if->mac_parameters.mac_default_lfn_key_index,
    };

    ws_llc_mngt_lfn_request(net_if, &req, NULL, MAC_DATA_NORMAL_PRIORITY);
}

void ws_mngt_lts_timer_cb(int ticks)
{
    struct net_if *net_if = protocol_stack_interface_info_get();

    ws_mngt_lts_send(net_if);
}
