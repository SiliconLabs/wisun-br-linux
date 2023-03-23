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

void wsbr_mac_store_rf_config_list(struct wsbr_ctxt *ctxt, struct iobuf_read *buf)
{
    const struct chan_params *chan_params = ws_regdb_chan_params(ctxt->config.ws_domain, ctxt->config.ws_chan_plan_id, ctxt->config.ws_class);
    const struct phy_params *phy_params = ws_regdb_phy_params(ctxt->config.ws_phy_mode_id, ctxt->config.ws_mode);
    bool rf_cfg_found = false;
    uint8_t rail_phy_mode_id;
    uint32_t chan0_freq;
    uint32_t chan_spacing;
    uint16_t chan_count;
    int offset_multiphy = -1;
    int offset_phy;
    bool is_submode;
    bool is_first;
    int i_pom = 0;

    memset(ctxt->phy_operating_modes, 0, ARRAY_SIZE(ctxt->phy_operating_modes));

    // MDR with custom domains are not yet supported
    if (!chan_params || !phy_params)
        return;

    while (iobuf_remaining_size(buf)) {
        offset_phy = buf->cnt;
        chan0_freq       = spinel_pop_u32(buf);
        chan_spacing     = spinel_pop_u32(buf);
        chan_count       = spinel_pop_u16(buf);
        rail_phy_mode_id = spinel_pop_u8(buf);
        is_submode       = spinel_pop_bool(buf);

        if (!is_submode)
            offset_multiphy = offset_phy;

        for (int i = 0; phy_params_table[i].phy_mode_id; i++) {
            if (phy_params_table[i].rail_phy_mode_id == rail_phy_mode_id &&
                phy_params_table[i].phy_mode_id      == phy_params->phy_mode_id &&
                chan0_freq   == chan_params->chan0_freq   &&
                chan_spacing == chan_params->chan_spacing &&
                chan_count   == chan_params->chan_count) {
                // TODO: support non standard OFDM-OFDM (same option) mode switch
                if (phy_params_table[i].modulation == MODULATION_OFDM)
                    return; // OFDM cannot be used as a base PHY
                rf_cfg_found = true;
                break;
            }
        }
        if (rf_cfg_found)
            break;
    }

    if (!rf_cfg_found)
        return;
    if (!ws_regdb_is_std(chan0_freq, chan_spacing, chan_count, phy_params->phy_mode_id))
        return;

    // add base PHY
    ctxt->phy_operating_modes[i_pom++] = phy_params->phy_mode_id;

    is_first = true;
    buf->cnt = offset_multiphy;
    while (iobuf_remaining_size(buf)) {
        chan0_freq       = spinel_pop_u32(buf);
        chan_spacing     = spinel_pop_u32(buf);
        chan_count       = spinel_pop_u16(buf);
        rail_phy_mode_id = spinel_pop_u8(buf);
        is_submode       = spinel_pop_bool(buf);

        if (is_first)
            is_first = false;
        else if (!is_submode)
            break; // multiphy end

        for (int i = 0; phy_params_table[i].phy_mode_id; i++) {
            if (phy_params_table[i].rail_phy_mode_id == rail_phy_mode_id) {
                if (phy_params_table[i].phy_mode_id == phy_params->phy_mode_id)
                    continue; // base PHY was already added
                if (!ws_regdb_is_std(chan0_freq, chan_spacing, chan_count, phy_params_table[i].phy_mode_id))
                    continue; // only add standard PHYs
                ctxt->phy_operating_modes[i_pom++] = phy_params_table[i].phy_mode_id;
                if (i_pom == sizeof(ctxt->phy_operating_modes) - 1)
                    return;
            }
        }
    }
}

static void print_rf_config(struct wsbr_ctxt *ctxt,
                            const struct phy_params *phy_params, const struct chan_params *chan_params,
                            uint32_t chan0_freq, uint32_t chan_spacing, uint16_t chan_count, uint8_t phy_mode_id)
{
    char str[256];
    bool is_std;
    int i;

    *str = '\0';
    if (chan_params)
        sprintf(str + strlen(str), " %-2s", val_to_str(chan_params->reg_domain, valid_ws_domains, "??"));
    else
        sprintf(str + strlen(str), " ??");

    if (chan_params && chan_params->op_class)
        sprintf(str + strlen(str), "   %d", chan_params->op_class);
    else if (chan_params)
        sprintf(str + strlen(str), "   -");
    else
        sprintf(str + strlen(str), "   ?");

    if (chan_params && chan_params->chan_plan_id)
        sprintf(str + strlen(str), "  %3d", chan_params->chan_plan_id);
    else if (chan_params)
        sprintf(str + strlen(str), "   --");
    else
        sprintf(str + strlen(str), "   ??");

    sprintf(str + strlen(str), "   %2d", phy_mode_id);

    if (phy_params && phy_params->op_mode)
        sprintf(str + strlen(str), "   %-2x", phy_params->op_mode);
    else if (phy_params)
        sprintf(str + strlen(str), "   --");
    else
        sprintf(str + strlen(str), "   ??");

    if (phy_params && phy_params->modulation == MODULATION_OFDM) {
        sprintf(str + strlen(str), "   OFDM");
        sprintf(str + strlen(str), "   %1d", phy_params->ofdm_mcs);
        sprintf(str + strlen(str), "    %1d", phy_params->ofdm_option);
        sprintf(str + strlen(str), "   --");
    } else if (phy_params && phy_params->modulation == MODULATION_2FSK) {
        sprintf(str + strlen(str), "    FSK");
        sprintf(str + strlen(str), "  --");
        sprintf(str + strlen(str), "   --");
        sprintf(str + strlen(str), "  %3s", val_to_str(phy_params->fsk_modulation_index, valid_fsk_modulation_indexes, "??"));
    } else {
        sprintf(str + strlen(str), "     ??");
        sprintf(str + strlen(str), "  ??");
        sprintf(str + strlen(str), "   ??");
        sprintf(str + strlen(str), "   ??");
    }

    if (phy_params)
        sprintf(str + strlen(str), " %4dkbps", phy_params->datarate / 1000);
    else
        sprintf(str + strlen(str), "   ??    ");

    sprintf(str + strlen(str), " %4.1fMHz", (double)chan0_freq / 1000000);
    sprintf(str + strlen(str), " %4dkHz", chan_spacing / 1000);
    sprintf(str + strlen(str), "  %3d", chan_count);

    is_std = false;
    if (chan_params) {
        for (i = 0; chan_params->valid_phy_modes[i]; i++) {
            if (chan_params->valid_phy_modes[i] == phy_mode_id) {
                is_std = true;
                break;
            }
        }
    }
    if (is_std)
        sprintf(str + strlen(str), "  yes");
    else
        sprintf(str + strlen(str), "   no");

    if (chan_params && chan_params->chan_allowed)
        sprintf(str + strlen(str), " %s", chan_params->chan_allowed);
    else if (chan_params)
        sprintf(str + strlen(str), " --");
    else
        sprintf(str + strlen(str), " ??");

    INFO("%s", str);
}

void wsbr_mac_print_rf_config_list(struct wsbr_ctxt *ctxt, struct iobuf_read *buf)
{
    uint32_t chan0_freq;
    uint32_t chan_spacing;
    uint8_t rail_phy_mode_id;
    uint16_t chan_count;
    bool phy_mode_found, chan_plan_found, is_submode;
    int i, j = 0;

    INFO("dom  cla chan phy  mode modula mcs ofdm mod    data    chan    chan  #chans is  chans");
    INFO("-ain -ss plan mode      -tion      opt. idx    rate    base    space        std allowed");
    while (iobuf_remaining_size(buf)) {
        chan0_freq = spinel_pop_u32(buf);
        chan_spacing = spinel_pop_u32(buf);
        chan_count = spinel_pop_u16(buf);
        rail_phy_mode_id = spinel_pop_u8(buf);
        is_submode = spinel_pop_u8(buf); // belongs to same multiphy as previous
        // the loops below allow several entries to match
        phy_mode_found = false;
        chan_plan_found = false;

        if (!is_submode)
            INFO("---------------------------------------------------------------------------------------");
        for (i = 0; phy_params_table[i].phy_mode_id; i++) {
            if (phy_params_table[i].rail_phy_mode_id == rail_phy_mode_id) {
                phy_mode_found = true;
                for (j = 0; chan_params_table[j].chan0_freq; j++) {
                    if (chan_params_table[j].chan0_freq == chan0_freq &&
                        chan_params_table[j].chan_spacing == chan_spacing &&
                        chan_params_table[j].chan_count == chan_count) {
                        chan_plan_found = true;
                        print_rf_config(ctxt, &phy_params_table[i], &chan_params_table[j],
                                        chan0_freq, chan_spacing, chan_count,
                                        phy_params_table[i].phy_mode_id);
                    }
                }
                if (!chan_plan_found)
                    print_rf_config(ctxt, &phy_params_table[i], NULL,
                                    chan0_freq, chan_spacing, chan_count,
                                    phy_params_table[i].phy_mode_id);
            }
        }
        if (!phy_mode_found)
            print_rf_config(ctxt, NULL, NULL, chan0_freq, chan_spacing, chan_count, rail_phy_mode_id);
    }
}

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

void wsbr_data_req_ext(const struct mac_api *api,
                       const struct mcps_data_req *data,
                       const struct mcps_data_req_ie_list *ie_ext)
{
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);
    struct net_if *cur = protocol_stack_interface_info_get_by_id(ctxt->rcp_if_id);
    struct ws_neighbor_class_entry *neighbor_ws;
    struct channel_list async_channel_list = {
        .channel_page = CHANNEL_PAGE_10,
    };
    struct iobuf_write frame = { };

    BUG_ON(ctxt != &g_ctxt);
    BUG_ON(data->TxAckReq && data->fhss_type == HIF_FHSS_TYPE_ASYNC);
    BUG_ON(data->DstAddrMode != MAC_ADDR_MODE_NONE &&
           (data->fhss_type == HIF_FHSS_TYPE_FFN_BC || data->fhss_type == HIF_FHSS_TYPE_LFN_BC || data->fhss_type == HIF_FHSS_TYPE_ASYNC));
    BUG_ON(data->DstAddrMode != MAC_ADDR_MODE_64_BIT &&
           (data->fhss_type == HIF_FHSS_TYPE_FFN_UC || data->fhss_type == HIF_FHSS_TYPE_LFN_UC || data->fhss_type == HIF_FHSS_TYPE_LFN_PA));
    BUG_ON(!ie_ext);
    BUG_ON(ie_ext->payloadIovLength > 2);
    BUG_ON(ie_ext->headerIovLength > 1);

    if (version_older_than(ctxt->rcp.version_api, 0, 22, 0)) {
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
        BUG_ON(!!neighbor_ws != !!data->DstAddrMode);
        wsbr_data_req_rebuild(&frame, api, &cur->mac_parameters, data, ie_ext);
        rcp_tx_req(frame.data, frame.len, neighbor_ws, data->msduHandle,
                   data->fhss_type, data->ExtendedFrameExchange,
                   data->priority, data->phy_id);
        iobuf_free(&frame);
    }

}

int8_t wsbr_mac_addr_set(const struct mac_api *api, const uint8_t *mac64)
{
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);

    BUG_ON(!api);
    BUG_ON(!mac64);
    BUG_ON(ctxt != &g_ctxt);

    if (memcmp(ctxt->dynamic_mac, mac64, 8))
        WARN("%s: Not implemented", __func__);

    memcpy(ctxt->dynamic_mac, mac64, 8);
    return 0;
}

int8_t wsbr_mac_addr_get(const struct mac_api *api,
                     mac_extended_address_type_e type, uint8_t *mac64)
{
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);

    BUG_ON(!api);
    BUG_ON(!mac64);
    BUG_ON(ctxt != &g_ctxt);

    switch (type) {
    case MAC_EXTENDED_READ_ONLY:
        memcpy(mac64, ctxt->rcp.eui64, 8);
        return 0;
    case MAC_EXTENDED_DYNAMIC:
        memcpy(mac64, ctxt->dynamic_mac, 8);
        return 0;
    default:
        BUG("Unknown address_type: %d", type);
    }
}
