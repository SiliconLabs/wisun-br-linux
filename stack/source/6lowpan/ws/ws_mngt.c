/*
 * Copyright (c) 2021-2022 Silicon Laboratories Inc. (www.silabs.com)
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
#include "stack/mac/mac_mcps.h"
#include "stack/mac/mlme.h"
#include "stack/source/6lowpan/ws/ws_bootstrap.h"
#include "stack/source/6lowpan/ws/ws_cfg_settings.h"
#include "stack/source/6lowpan/ws/ws_common.h"
#include "stack/source/6lowpan/ws/ws_common_defines.h"
#include "stack/source/6lowpan/ws/ws_mngt.h"
#include "stack/source/6lowpan/ws/ws_ie_lib.h"
#include "stack/source/6lowpan/ws/ws_ie_validation.h"
#include "stack/source/6lowpan/ws/ws_llc.h"
#include "stack/source/nwk_interface/protocol.h"
#include "common/log.h"
#include "common/named_values.h"
#include "common/trickle.h"

static bool ws_mngt_ie_utt_validate(const struct mcps_data_ie_list *ie_ext,
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
                                   const struct mcps_data_ie_list *ie_ext,
                                   struct ws_us_ie *ie_us,
                                   uint8_t frame_type)
{
    // FIXME: see comment in ws_llc_asynch_indication
    if (!ws_wp_nested_us_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, ie_us)) {
        TRACE(TR_DROP, "drop %-9s: missing US-IE", tr_ws_frame(frame_type));
        return false;
    }
    return ws_ie_validate_us(&net_if->ws_info, ie_us);
}

static bool ws_mngt_ie_netname_validate(struct net_if *net_if,
                                        const struct mcps_data_ie_list *ie_ext,
                                        uint8_t frame_type)
{
    ws_wp_netname_t ie_netname;

    // FIXME: see comment in ws_llc_asynch_indication
    if (!ws_wp_nested_netname_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, &ie_netname)) {
        TRACE(TR_DROP, "drop %-9s: missing NETNAME-IE", tr_ws_frame(frame_type));
        return false;
    }
    return ws_ie_validate_netname(&net_if->ws_info, &ie_netname);
}

static void ws_mngt_ie_pom_handle(struct net_if *net_if,
                                  const struct mcps_data_ind *data,
                                  const struct mcps_data_ie_list *ie_ext)
{
    mac_neighbor_table_entry_t *neighbor;
    ws_pom_ie_t ie_pom;

    neighbor = mac_neighbor_table_address_discover(net_if->mac_parameters.mac_neighbor_table,
                                                   data->SrcAddr, ADDR_802_15_4_LONG);
    if (!neighbor)
        return;
    if (!ws_wp_nested_pom_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, &ie_pom))
        return;
    mac_neighbor_update_pom(neighbor, ie_pom.phy_op_mode_number, ie_pom.phy_op_mode_id, ie_pom.mdr_command_capable);
}

void ws_mngt_pa_analyze(struct net_if *net_if,
                        const struct mcps_data_ind *data,
                        const struct mcps_data_ie_list *ie_ext)
{
    ws_pan_information_t pan_information;
    ws_utt_ie_t ie_utt;
    ws_us_ie_t ie_us;

    if (!ws_mngt_ie_utt_validate(ie_ext, &ie_utt, WS_FT_PA))
        return;
    if (!ws_mngt_ie_us_validate(net_if, ie_ext, &ie_us, WS_FT_PA))
        return;
    // FIXME: see comment in ws_llc_asynch_indication
    if (!ws_wp_nested_pan_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, &pan_information)) {
        TRACE(TR_DROP, "drop %-9s: missing PAN-IE", tr_ws_frame(WS_FT_PA));
        return;
    }
    if (!ws_mngt_ie_netname_validate(net_if, ie_ext, WS_FT_PA))
        return;

    if (data->SrcPANId != net_if->ws_info.network_pan_id) {
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
                         const struct mcps_data_ie_list *ie_ext)
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
                        const struct mcps_data_ie_list *ie_ext)
{
    llc_neighbour_req_t neighbor_info;
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
    // FIXME: see comment in ws_llc_asynch_indication
    if (!ws_wp_nested_bs_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, &ie_bs)) {
        TRACE(TR_DROP, "drop %-9s: missing BS-IE", tr_ws_frame(WS_FT_PC));
        return;
    }
    // FIXME: see comment in ws_llc_asynch_indication
    if (!ws_wp_nested_panver_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, &ws_pan_version)) {
        TRACE(TR_DROP, "drop %-9s: missing PANVER-IE", tr_ws_frame(WS_FT_PC));
        return;
    }

    if (data->SrcPANId != net_if->ws_info.network_pan_id) {
        TRACE(TR_DROP, "drop %-9s: PAN ID mismatch", tr_ws_frame(WS_FT_PC));
        return;
    }

    if (net_if->ws_info.pan_information.pan_version == ws_pan_version)
        trickle_consistent_heard(&net_if->ws_info.mngt.trickle_pc);
    else
        trickle_inconsistent_heard(&net_if->ws_info.mngt.trickle_pc,
                                   &net_if->ws_info.mngt.trickle_params);

    if (ws_bootstrap_neighbor_get(net_if, data->SrcAddr, &neighbor_info)) {
        ws_neighbor_class_ut_update(neighbor_info.ws_neighbor, ie_utt.ufsi, data->timestamp, data->SrcAddr);
        ws_neighbor_class_us_update(net_if, neighbor_info.ws_neighbor, &ie_us.chan_plan,
                                    ie_us.dwell_interval, data->SrcAddr);
    }
}

void ws_mngt_pcs_analyze(struct net_if *net_if,
                         const struct mcps_data_ind *data,
                         const struct mcps_data_ie_list *ie_ext)
{
    llc_neighbour_req_t neighbor_info;
    ws_utt_ie_t ie_utt;
    ws_us_ie_t ie_us;

    if (!ws_mngt_ie_utt_validate(ie_ext, &ie_utt, WS_FT_PCS))
        return;
    if (!ws_mngt_ie_us_validate(net_if, ie_ext, &ie_us, WS_FT_PCS))
        return;
    if (!ws_mngt_ie_netname_validate(net_if, ie_ext, WS_FT_PCS))
        return;

    if (data->SrcPANId != net_if->ws_info.network_pan_id) {
        TRACE(TR_DROP, "drop %-9s: PAN ID mismatch", tr_ws_frame(WS_FT_PCS));
        return;
    }

    trickle_inconsistent_heard(&net_if->ws_info.mngt.trickle_pc,
                               &net_if->ws_info.mngt.trickle_params);

    if (ws_bootstrap_neighbor_get(net_if, data->SrcAddr, &neighbor_info)) {
        ws_neighbor_class_ut_update(neighbor_info.ws_neighbor, ie_utt.ufsi, data->timestamp, data->SrcAddr);
        ws_neighbor_class_us_update(net_if, neighbor_info.ws_neighbor, &ie_us.chan_plan,
                                    ie_us.dwell_interval, data->SrcAddr);
    }
}

void ws_mngt_lpas_analyze(struct net_if *net_if,
                          const struct mcps_data_ind *data,
                          const struct mcps_data_ie_list *ie_ext)
{
    llc_neighbour_req_t neighbor;
    struct ws_lutt_ie ie_lutt;
    struct ws_lus_ie ie_lus;
    struct ws_lnd_ie ie_lnd;
    struct ws_lcp_ie ie_lcp;
    struct ws_nr_ie ie_nr;
    uint8_t rsl;

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
    // FIXME: see comment in ws_llc_asynch_indication
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
    rsl = ws_neighbor_class_rsl_from_dbm_calculate(data->signal_dbm);
    if (rsl < (DEVICE_MIN_SENS + ie_lnd.response_threshold)) {
        TRACE(TR_DROP, "drop %-9s: RSL below LND-IE response threshold", tr_ws_frame(WS_FT_LPAS));
        return;
    }

    if (!ws_bootstrap_neighbor_get(net_if, data->SrcAddr, &neighbor) &&
        !ws_bootstrap_neighbor_add(net_if, data->SrcAddr, &neighbor, WS_NR_ROLE_LFN)) {
        TRACE(TR_DROP, "drop %-9s: could not allocate neighbor %s", tr_ws_frame(WS_FT_LPAS), tr_eui64(data->SrcAddr));
        return;
    }

    // TODO
    WARN("LPAS handling not yet implemented");
}
