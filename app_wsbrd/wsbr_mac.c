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
#include "common/os_types.h"
#include "common/named_values.h"
#include "common/parsers.h"
#include "common/pcapng.h"
#include "common/spinel_defs.h"
#include "common/spinel_buffer.h"
#include "common/iobuf.h"
#include "common/utils.h"
#include "common/version.h"
#include "common/ws_regdb.h"

#include "nwk_interface/protocol.h"
#include "6lowpan/ws/ws_bootstrap.h"
#include "6lowpan/ws/ws_common_defines.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_config.h"
#include "6lowpan/ws/ws_llc.h"
#include "stack/mac/mac_mcps.h"
#include "stack/mac/mac_api.h"
#include "stack/mac/channel_list.h"
#include "stack/mac/mlme.h"
#include "stack/ws_management_api.h"
#include "stack/ws_bbr_api.h"

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

struct ws_neighbor_class_entry *wsbr_get_neighbor(struct net_if *cur, const uint8_t eui64[8])
{
    ws_neighbor_temp_class_t *neighbor_ws_tmp;
    llc_neighbour_req_t neighbor_llc;

    neighbor_ws_tmp = ws_llc_get_eapol_temp_entry(cur, eui64);
    if (!neighbor_ws_tmp)
        neighbor_ws_tmp = ws_llc_get_multicast_temp_entry(cur, eui64);
    if (neighbor_ws_tmp)
        return &neighbor_ws_tmp->neigh_info_list;
    if (ws_bootstrap_neighbor_get(cur, eui64, &neighbor_llc))
        return neighbor_llc.ws_neighbor;
    else
        return NULL;
}

void wsbr_data_req_ext(struct net_if *cur,
                       const struct mcps_data_req *data,
                       const struct mcps_data_req_ie_list *ie_ext)
{
    struct ws_neighbor_class_entry neighbor_ws_dummy = { 0 };
    struct ws_neighbor_class_entry *neighbor_ws;
    struct channel_list async_channel_list = {
        .channel_page = CHANNEL_PAGE_10,
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

    if (version_older_than(g_ctxt.rcp.version_api, 0, 25, 0)) {
        if (cur->ws_info.fhss_conf.ws_uc_channel_function == WS_FIXED_CHANNEL) {
            async_channel_list.next_channel_number = cur->ws_info.fhss_conf.unicast_fixed_channel;
            bitset(async_channel_list.channel_mask, async_channel_list.next_channel_number);
        } else {
            memcpy(async_channel_list.channel_mask,
                   cur->ws_info.fhss_conf.domain_channel_mask,
                   sizeof(async_channel_list.channel_mask));
        }

        rcp_tx_req_legacy(data,
                          (ie_ext->headerIovLength >= 1)  ? &ie_ext->headerIeVectorList[0]  : NULL,
                          (ie_ext->payloadIovLength >= 1) ? &ie_ext->payloadIeVectorList[0] : NULL,
                          (ie_ext->payloadIovLength >= 2) ? &ie_ext->payloadIeVectorList[1] : NULL,
                          data->fhss_type == HIF_FHSS_TYPE_ASYNC ? &async_channel_list : NULL);
    } else {
        neighbor_ws = wsbr_get_neighbor(cur, data->DstAddr);
        if (data->DstAddrMode && !neighbor_ws) {
            WARN("%s: neighbor timeout before packet send", __func__);
            // Send 0 initialized FHSS timings to the RCP, which will return a
            // confirmation error.
            neighbor_ws = &neighbor_ws_dummy;
        }
        wsbr_data_req_rebuild(&frame, cur->rcp, &cur->mac_parameters, data, ie_ext);
        rcp_tx_req(frame.data, frame.len, neighbor_ws, data->msduHandle,
                   data->fhss_type, data->ExtendedFrameExchange,
                   data->priority, data->phy_id);
        iobuf_free(&frame);
    }

}
