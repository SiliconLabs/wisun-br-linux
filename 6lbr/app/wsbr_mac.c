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

/* MAC API implementation */
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "common/log.h"
#include "common/bus.h"
#include "common/named_values.h"
#include "common/parsers.h"
#include "common/pcapng.h"
#include "common/spinel.h"
#include "common/bits.h"
#include "common/hif.h"
#include "common/iobuf.h"
#include "common/memutils.h"
#include "common/version.h"
#include "common/ws_regdb.h"
#include "common/specs/ieee802154.h"

#include "net/protocol.h"
#include "ws/ws_bootstrap.h"
#include "ws/ws_common.h"
#include "ws/ws_config.h"
#include "ws/ws_llc.h"

#include "frame_helpers.h"
#include "version.h"
#include "wsbr.h"
#include "rcp_api.h"
#include "wsbr_mac.h"
#include "wsbr_pcapng.h"
#include "timers.h"
#include "tun.h"
#include "dbus.h"
#include "commandline_values.h"

struct ws_neigh *wsbr_get_neighbor(struct net_if *cur, const uint8_t eui64[8])
{
    return ws_neigh_get(&cur->ws_info.neighbor_storage, eui64);
}

void wsbr_data_req_ext(struct net_if *cur,
                       const struct mcps_data_req *data,
                       const struct mcps_data_req_ie_list *ie_ext)
{
    struct fhss_ws_neighbor_timing_info fhss_data;
    struct ws_neigh *neighbor_ws;
    struct hif_rate_info rate_list[4] = {
        {
            .phy_mode_id  = data->phy_id,
            .tx_attempts  = 20,
            .tx_power_dbm = INT8_MAX,
        },
    };
    struct mcps_data_rx_ie_list cnf_fail_ie = { };
    struct mcps_data_cnf cnf_fail = {
        .hif.handle = data->msduHandle,
        .hif.status = HIF_STATUS_TIMEDOUT,
    };
    struct iobuf_write frame = { };

    BUG_ON(data->TxAckReq && data->fhss_type == HIF_FHSS_TYPE_ASYNC);
    BUG_ON(data->DstAddrMode != MAC_ADDR_MODE_NONE &&
           (data->fhss_type == HIF_FHSS_TYPE_FFN_BC || data->fhss_type == HIF_FHSS_TYPE_LFN_BC || data->fhss_type == HIF_FHSS_TYPE_ASYNC));
    BUG_ON(data->DstAddrMode != MAC_ADDR_MODE_64_BIT &&
           (data->fhss_type == HIF_FHSS_TYPE_FFN_UC || data->fhss_type == HIF_FHSS_TYPE_LFN_UC || data->fhss_type == HIF_FHSS_TYPE_LFN_PA));
    BUG_ON(!ie_ext);
    BUG_ON(ie_ext->payloadIovLength > 2);
    BUG_ON(ie_ext->headerIovLength > 1);

    neighbor_ws = wsbr_get_neighbor(cur, data->DstAddr);
    if (data->DstAddrMode && !neighbor_ws) {
        WARN("%s: neighbor timeout before packet send", __func__);
        ws_llc_mac_confirm_cb(cur->id, &cnf_fail, &cnf_fail_ie);
        return;
    }
    if (neighbor_ws) {
        // After a reboot we may not have secured fhss data yet
        if (data->fhss_type == HIF_FHSS_TYPE_FFN_UC)
            fhss_data = neighbor_ws->fhss_data.ffn.uc_dwell_interval_ms ? neighbor_ws->fhss_data : neighbor_ws->fhss_data_unsecured;
        if (data->fhss_type == HIF_FHSS_TYPE_LFN_UC) {
            fhss_data = neighbor_ws->fhss_data.lfn.uc_listen_interval_ms ? neighbor_ws->fhss_data : neighbor_ws->fhss_data_unsecured;

            // We may not have received any LCP-IE along with secured frames,
            // if that's the case, we use unsecured information by default.
            // This is necessary as an LFN MUST send this IE in LPAS only.
            // Note that this is a potential security issue, an attacker could
            // easily send this IE in an LPAS and change the information of an
            // authenticated LFN that has never sent a secured frame with LCP-IE.
            if (!fhss_data.uc_chan_count) {
                fhss_data.uc_chan_count = neighbor_ws->fhss_data_unsecured.uc_chan_count;
                fhss_data.uc_chan_func = neighbor_ws->fhss_data_unsecured.uc_chan_func;
                fhss_data.uc_chan_fixed = neighbor_ws->fhss_data_unsecured.uc_chan_fixed;
                fhss_data.uc_channel_list = neighbor_ws->fhss_data_unsecured.uc_channel_list;
            }
        }
        // This is necessary to handle potential reconnection
        if (data->frame_type == WS_FT_EAPOL || data->frame_type == WS_FT_LPA || data->frame_type == WS_FT_LPC)
            fhss_data = neighbor_ws->fhss_data_unsecured;
    }

    wsbr_data_req_rebuild(&frame, cur->rcp, data, ie_ext, cur->ws_info.pan_information.pan_id);
    BUG_ON(data->ExtendedFrameExchange);
    rcp_req_data_tx(cur->rcp, frame.data, frame.len,
                    data->msduHandle,  data->fhss_type, neighbor_ws ? &fhss_data : NULL,
                    neighbor_ws ? neighbor_ws->frame_counter_min : NULL,
                    data->phy_id ? rate_list : NULL);
    iobuf_free(&frame);
}

void wsbr_tx_cnf(struct rcp *rcp, const struct hif_tx_cnf *cnf)
{
    struct wsbr_ctxt *ctxt = container_of(rcp, struct wsbr_ctxt, rcp);
    struct mcps_data_cnf mcps_cnf = { .hif = *cnf };
    struct mcps_data_rx_ie_list mcps_ie = { };
    int ret;

    if (cnf->frame_len) {
        ret = wsbr_data_cnf_parse(cnf->frame, cnf->frame_len, &mcps_cnf, &mcps_ie);
        WARN_ON(ret < 0, "invalid ack frame");
    }
    ws_llc_mac_confirm_cb(ctxt->net_if.id, &mcps_cnf, &mcps_ie);
}

void wsbr_rx_ind(struct rcp *rcp, const struct hif_rx_ind *ind)
{
    struct wsbr_ctxt *ctxt = container_of(rcp, struct wsbr_ctxt, rcp);
    struct mcps_data_ind mcps_ind = { .hif = *ind };
    struct mcps_data_rx_ie_list mcps_ie = { };
    int ret;

    ret = wsbr_data_ind_parse(ind->frame, ind->frame_len,
                              &mcps_ind, &mcps_ie,
                              ctxt->net_if.ws_info.pan_information.pan_id);
    if (ret < 0)
        return;
    ws_llc_mac_indication_cb(ctxt->net_if.id, &mcps_ind, &mcps_ie);
}
