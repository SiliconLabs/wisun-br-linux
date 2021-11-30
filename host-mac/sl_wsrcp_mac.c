/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include "nanostack/mlme.h"
#include "nanostack/sw_mac.h"
#include "nanostack/fhss_api.h"
#include "nanostack/fhss_config.h"
#include "nanostack/net_fhss.h"
#include "nanostack/source/6LoWPAN/ws/ws_common_defines.h"

#include "version.h"
#include "sl_wsrcp.h"
#include "sl_wsrcp_mac.h"
#include "hal_fhss_timer.h"
#include "host-common/bus_uart.h"
#include "host-common/spinel.h"
#include "host-common/spinel_buffer.h"
#include "host-common/utils.h"
#include "host-common/log.h"

static uint8_t wsbr_get_spinel_hdr(struct wsmac_ctxt *ctxt)
{
    uint8_t hdr = FIELD_PREP(0xC0, 0x2) | FIELD_PREP(0x30, ctxt->spinel_iid);

    ctxt->spinel_tid = (ctxt->spinel_tid + 1) % 0x10;
    if (!ctxt->spinel_tid)
        ctxt->spinel_tid = 1;
    hdr |= FIELD_PREP(0x0F, ctxt->spinel_tid);
    return hdr;
}

static void wsmac_spinel_set_bool(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    bool data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };

    data = spinel_pop_bool(buf);
    BUG_ON(spinel_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_u8(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    uint8_t data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };

    data = spinel_pop_u8(buf);
    BUG_ON(spinel_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_u16(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    uint16_t data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };

    data = spinel_pop_u16(buf);
    BUG_ON(spinel_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_u32(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    uint32_t data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };

    data = spinel_pop_u32(buf);
    BUG_ON(spinel_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_eui64(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    uint8_t data[8];
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = data,
        .value_size = sizeof(data),
    };

    spinel_pop_fixed_u8_array(buf, data, 8);
    BUG_ON(spinel_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_data(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    mlme_set_t req = {
        .attr = attr,
    };

    req.value_size = spinel_pop_raw_ptr(buf, (uint8_t **)&req.value_pointer, -1, false);
    BUG_ON(spinel_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_cca_threshold_start(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    uint8_t data[4];
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = data,
        .value_size = sizeof(data),
    };

    spinel_pop_fixed_u8_array(buf, data, 4);
    BUG_ON(spinel_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_multi_csma_parameters(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    struct mlme_multi_csma_ca_s data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };

    data.number_of_csma_ca_periods = spinel_pop_u8(buf);
    data.multi_cca_interval        = spinel_pop_u16(buf);
    BUG_ON(spinel_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_rf_configuration(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    struct phy_rf_channel_configuration_s data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };

    data.channel_0_center_frequency = spinel_pop_u32(buf);
    data.channel_spacing            = spinel_pop_u32(buf);
    data.datarate                   = spinel_pop_u32(buf);
    data.number_of_channels         = spinel_pop_u16(buf);
    data.modulation                 = spinel_pop_u8(buf);
    data.modulation_index           = spinel_pop_u8(buf);
    BUG_ON(spinel_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_device_table(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    struct mlme_device_descriptor_s data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };

    req.attr_index    = spinel_pop_u8(buf);
    data.PANId        = spinel_pop_u16(buf);
    data.ShortAddress = spinel_pop_u16(buf);
    spinel_pop_fixed_u8_array(buf, data.ExtAddress, 8);
    data.FrameCounter = spinel_pop_u32(buf);
    data.Exempt       = spinel_pop_bool(buf);
    BUG_ON(spinel_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_key_table(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    mlme_key_id_lookup_descriptor_t descr = { };
    mlme_key_descriptor_entry_t data = {
        .KeyIdLookupList = &descr,
    };
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };
    int lookup_len;

    BUG_ON(attr != macKeyTable);
    BUG_ON(sizeof(data.Key) != 16);

    req.attr_index = spinel_pop_u8(buf);
    spinel_pop_fixed_u8_array(buf, data.Key, 16);
    lookup_len = spinel_pop_data(buf, data.KeyIdLookupList->LookupData,
                                 sizeof(data.KeyIdLookupList->LookupData));
    BUG_ON(spinel_remaining_size(buf));
    if (lookup_len) {
        data.KeyIdLookupListEntries = 1;
        if (lookup_len == 9)
            data.KeyIdLookupList->LookupDataSize = 1;
        else
            BUG_ON(lookup_len != 5);
    }
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_request_restart(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    mlme_request_restart_config_t data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };

    BUG_ON(attr != macRequestRestart);
    data.cca_failure_restart_max = spinel_pop_u8(buf);
    data.tx_failure_restart_max  = spinel_pop_u8(buf);
    data.blacklist_min_ms        = spinel_pop_u16(buf);
    data.blacklist_max_ms        = spinel_pop_u16(buf);
    BUG_ON(spinel_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_frame_counter(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    uint32_t data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };

    BUG_ON(attr != macFrameCounter);
    req.attr_index = spinel_pop_int(buf);
    data           = spinel_pop_u32(buf);
    BUG_ON(spinel_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_fhss_set_parent(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    broadcast_timing_info_t bc_timing_info;
    uint8_t eui64[8];
    bool force_synch;

    spinel_pop_fixed_u8_array(buf, eui64, 8);
    force_synch                               = spinel_pop_bool(buf);
    bc_timing_info.broadcast_channel_function = spinel_pop_u8(buf);
    bc_timing_info.broadcast_dwell_interval   = spinel_pop_u8(buf);
    bc_timing_info.fixed_channel              = spinel_pop_u16(buf);
    bc_timing_info.broadcast_slot             = spinel_pop_u16(buf);
    bc_timing_info.broadcast_schedule_id      = spinel_pop_u16(buf);
    bc_timing_info.broadcast_interval_offset  = spinel_pop_u32(buf);
    bc_timing_info.broadcast_interval         = spinel_pop_u32(buf);
    bc_timing_info.bt_rx_timestamp            = spinel_pop_u32(buf);
    BUG_ON(spinel_remaining_size(buf));
    ns_fhss_ws_set_parent(ctxt->fhss_api, eui64, &bc_timing_info, force_synch);
}

static void wsmac_spinel_set_frame_counter_per_key(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    bool data;

    data = spinel_pop_bool(buf);
    BUG_ON(spinel_remaining_size(buf));
    ns_sw_mac_enable_frame_counter_per_key(ctxt->rcp_mac_api, data);
}

static void wsmac_spinel_fhss_set_tx_allowance_level(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    int global_level, ef_level;

    global_level = spinel_pop_int(buf);
    ef_level     = spinel_pop_int(buf);
    BUG_ON(spinel_remaining_size(buf));
    ns_fhss_ws_set_tx_allowance_level(ctxt->fhss_api, global_level, ef_level);
}

static void wsmac_spinel_fhss_update_neighbor(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    struct fhss_ws_neighbor_timing_info *fhss_data = NULL;
    uint8_t eui64[8];
    int i;

    spinel_pop_fixed_u8_array(buf, eui64, 8);
    for (i = 0; i < ARRAY_SIZE(ctxt->neighbor_timings); i++)
        if (!memcmp(ctxt->neighbor_timings[i].eui64, eui64, 8))
            fhss_data = &ctxt->neighbor_timings[i].val;
    if (!fhss_data) {
        DEBUG("add new entry");
        for (i = 0; i < ARRAY_SIZE(ctxt->neighbor_timings); i++) {
            if (!memcmp(ctxt->neighbor_timings[i].eui64,
                        "\x00\x00\x00\x00\x00\x00\x00\x00", 8)) {
                fhss_data = &ctxt->neighbor_timings[i].val;
                memcpy(ctxt->neighbor_timings[i].eui64, eui64, 8);
                break;
            }
        }
        BUG_ON(i == ARRAY_SIZE(ctxt->neighbor_timings), "full");
    }

    fhss_data->clock_drift                               = spinel_pop_u8(buf);
    fhss_data->timing_accuracy                           = spinel_pop_u8(buf);
    fhss_data->uc_channel_list.channel_count             = spinel_pop_u16(buf);
    spinel_pop_fixed_u32_array(buf, fhss_data->uc_channel_list.channel_mask, 8);
    fhss_data->uc_timing_info.unicast_channel_function   = spinel_pop_u8(buf);
    fhss_data->uc_timing_info.unicast_dwell_interval     = spinel_pop_u8(buf);
    fhss_data->uc_timing_info.unicast_number_of_channels = spinel_pop_u16(buf);
    fhss_data->uc_timing_info.fixed_channel              = spinel_pop_u16(buf);
    fhss_data->uc_timing_info.ufsi                       = spinel_pop_u32(buf);
    fhss_data->uc_timing_info.utt_rx_timestamp           = spinel_pop_u32(buf);
    BUG_ON(spinel_remaining_size(buf));
}

static void wsmac_spinel_fhss_drop_neighbor(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    uint8_t eui64[8];
    int i;

    spinel_pop_fixed_u8_array(buf, eui64, 8);
    for (i = 0; i < ARRAY_SIZE(ctxt->neighbor_timings); i++)
        if (!memcmp(ctxt->neighbor_timings[i].eui64, eui64, 8))
            break;
    BUG_ON(i == ARRAY_SIZE(ctxt->neighbor_timings), "not found");
    memset(ctxt->neighbor_timings[i].eui64, 0, 8);
}

static fhss_ws_neighbor_timing_info_t *wsmac_fhss_get_neighbor_info(const fhss_api_t *fhss_api, uint8_t eui64[8])
{
    struct wsmac_ctxt *ctxt = &g_ctxt;
    int i;

    BUG_ON(fhss_api != ctxt->fhss_api);
    for (i = 0; i < ARRAY_SIZE(ctxt->neighbor_timings); i++)
        if (!memcmp(ctxt->neighbor_timings[i].eui64, eui64, sizeof(uint8_t[8])))
            return &ctxt->neighbor_timings[i].val;
    return NULL;
}

static void wsmac_spinel_fhss_create(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    struct fhss_ws_configuration config = { };

    config.ws_uc_channel_function  = spinel_pop_u8(buf);
    config.ws_bc_channel_function  = spinel_pop_u8(buf);
    config.bsi                     = spinel_pop_u16(buf);
    config.fhss_uc_dwell_interval  = spinel_pop_u8(buf);
    config.fhss_broadcast_interval = spinel_pop_u32(buf);
    config.fhss_bc_dwell_interval  = spinel_pop_u8(buf);
    config.unicast_fixed_channel   = spinel_pop_u8(buf);
    config.broadcast_fixed_channel = spinel_pop_u8(buf);
    spinel_pop_fixed_u32_array(buf, config.channel_mask, 8);
    spinel_pop_fixed_u32_array(buf, config.unicast_channel_mask, 8);
    config.channel_mask_size       = spinel_pop_u16(buf);
    config.config_parameters.number_of_channel_retries = spinel_pop_u8(buf);
    BUG_ON(spinel_remaining_size(buf));
    ctxt->fhss_api = ns_fhss_ws_create(&config, &wsmac_fhss);
    BUG_ON(!ctxt->fhss_api);
    ns_fhss_set_neighbor_info_fp(ctxt->fhss_api, wsmac_fhss_get_neighbor_info);
}

static void wsmac_spinel_fhss_delete(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    BUG_ON(spinel_remaining_size(buf));
    ns_fhss_delete(ctxt->fhss_api);
    ctxt->fhss_api = NULL;
}

static void wsmac_spinel_fhss_set_conf(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    struct fhss_ws_configuration config = { };

    config.ws_uc_channel_function  = spinel_pop_u8(buf);
    config.ws_bc_channel_function  = spinel_pop_u8(buf);
    config.bsi                     = spinel_pop_u16(buf);
    config.fhss_uc_dwell_interval  = spinel_pop_u8(buf);
    config.fhss_broadcast_interval = spinel_pop_u32(buf);
    config.fhss_bc_dwell_interval  = spinel_pop_u8(buf);
    config.unicast_fixed_channel   = spinel_pop_u8(buf);
    config.broadcast_fixed_channel = spinel_pop_u8(buf);
    spinel_pop_fixed_u32_array(buf, config.channel_mask, 8);
    spinel_pop_fixed_u32_array(buf, config.unicast_channel_mask, 8);
    config.channel_mask_size       = spinel_pop_u16(buf);
    config.config_parameters.number_of_channel_retries = spinel_pop_u8(buf);
    BUG_ON(spinel_remaining_size(buf));
    ns_fhss_ws_configuration_set(ctxt->fhss_api, &config);
}

static void wsmac_spinel_fhss_set_hop_count(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    uint8_t data;

    data = spinel_pop_u8(buf);
    BUG_ON(spinel_remaining_size(buf));
    ns_fhss_ws_set_hop_count(ctxt->fhss_api, data);
}

static void wsmac_spinel_fhss_register(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    struct fhss_api *fhss_api = ns_sw_mac_get_fhss_api(ctxt->rcp_mac_api);

    BUG_ON(spinel_remaining_size(buf));
    BUG_ON(fhss_api, "fhss_api already regstered");
    BUG_ON(!ctxt->fhss_api, "fhss_api not yet created");
    ns_sw_mac_fhss_register(ctxt->rcp_mac_api, ctxt->fhss_api);
}

static void wsmac_spinel_fhss_unregister(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    struct fhss_api *fhss_api = ns_sw_mac_get_fhss_api(ctxt->rcp_mac_api);

    BUG_ON(spinel_remaining_size(buf));
    BUG_ON(fhss_api != ctxt->fhss_api);
    ns_sw_mac_fhss_unregister(ctxt->rcp_mac_api);
    ctxt->fhss_api = NULL;
}

static void wsmac_spinel_ws_start(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    mlme_start_t req = { };

    req.PANId           = spinel_pop_u16(buf);
    req.LogicalChannel  = spinel_pop_u8(buf);
    req.ChannelPage     = spinel_pop_u8(buf);
    req.StartTime       = spinel_pop_u32(buf);
    req.BeaconOrder     = spinel_pop_u8(buf);
    req.SuperframeOrder = spinel_pop_u8(buf);
    req.PANCoordinator  = spinel_pop_bool(buf);
    BUG_ON(spinel_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_START, &req);
}

static void wsmac_spinel_ws_reset(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    mlme_reset_t req = { };

    req.SetDefaultPIB = spinel_pop_bool(buf);
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_RESET, &req);
}

static void wsmac_spinel_data_req(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf)
{
    struct mcps_data_req_s data;
    struct mcps_data_req_ie_list ie_ext = { };
    struct channel_list_s async_channel_list;
    struct msdu_malloc_info *malloc_info;
    uint16_t prio;
    int len;

    data.msduLength                 = spinel_pop_u16(buf);
    data.msdu = malloc(data.msduLength);
    spinel_pop_raw(buf, data.msdu, data.msduLength, true);
    data.SrcAddrMode                = spinel_pop_u8(buf);
    data.DstAddrMode                = spinel_pop_u8(buf);
    data.DstPANId                   = spinel_pop_u16(buf);
    spinel_pop_fixed_u8_array(buf, data.DstAddr, 8);
    data.msduHandle                 = spinel_pop_u8(buf);
    data.TxAckReq                   = spinel_pop_bool(buf);
    data.InDirectTx                 = spinel_pop_bool(buf);
    data.PendingBit                 = spinel_pop_bool(buf);
    data.SeqNumSuppressed           = spinel_pop_bool(buf);
    data.PanIdSuppressed            = spinel_pop_bool(buf);
    data.ExtendedFrameExchange      = spinel_pop_bool(buf);
    data.Key.SecurityLevel          = spinel_pop_u8(buf);
    data.Key.KeyIdMode              = spinel_pop_u8(buf);
    data.Key.KeyIndex               = spinel_pop_u8(buf);
    spinel_pop_fixed_u8_array(buf, data.Key.Keysource, 8);
    prio                            = spinel_pop_u16(buf);
    async_channel_list.channel_page = spinel_pop_int(buf);
    spinel_pop_fixed_u32_array(buf, async_channel_list.channel_mask, 8);

    len = spinel_pop_u16(buf);
    if (len) {
        ie_ext.payloadIovLength = 1;
        ie_ext.payloadIeVectorList = malloc(sizeof(struct ns_ie_iovec));
        ie_ext.payloadIeVectorList->iovLen = len;
        ie_ext.payloadIeVectorList->ieBase = malloc(len);
        spinel_pop_raw(buf, ie_ext.payloadIeVectorList->ieBase, len, true);
    }

    len = spinel_pop_u16(buf);
    if (len) {
        ie_ext.headerIovLength = 1;
        ie_ext.headerIeVectorList = malloc(sizeof(struct ns_ie_iovec));
        ie_ext.headerIeVectorList->iovLen = len;
        ie_ext.headerIeVectorList->ieBase = malloc(len);
        spinel_pop_raw(buf, ie_ext.headerIeVectorList->ieBase, len, true);
    }
    BUG_ON(spinel_remaining_size(buf));

    malloc_info = malloc(sizeof(*malloc_info));
    malloc_info->payload = ie_ext.payloadIeVectorList;
    malloc_info->header = ie_ext.headerIeVectorList;
    malloc_info->msdu = data.msdu;
    malloc_info->msduHandle = data.msduHandle;
    memset(&malloc_info->list, 0, sizeof(struct slist));
    slist_push(&ctxt->msdu_malloc_list, &malloc_info->list);

    // FIXME: replace 0 by the Phy ID provided by the Host
    if (async_channel_list.channel_page != CHANNEL_PAGE_UNDEFINED)
        ctxt->rcp_mac_api->mcps_data_req_ext(ctxt->rcp_mac_api, &data, &ie_ext, &async_channel_list, prio, 0);
    else
        ctxt->rcp_mac_api->mcps_data_req_ext(ctxt->rcp_mac_api, &data, &ie_ext, NULL, prio, 0);
}

static const struct {
    mlme_attr_t attr;
    void (*prop_set)(struct wsmac_ctxt *ctxt, mlme_attr_t attr, struct spinel_buffer *buf);
    unsigned int prop;
} mlme_prop_cstr[] = {
    { macRxOnWhenIdle,                 wsmac_spinel_set_bool,                  SPINEL_PROP_WS_RX_ON_WHEN_IDLE,                  },
    { macSecurityEnabled,              wsmac_spinel_set_bool,                  SPINEL_PROP_WS_SECURITY_ENABLED,                 },
    { macAcceptByPassUnknowDevice,     wsmac_spinel_set_bool,                  SPINEL_PROP_WS_ACCEPT_BYPASS_UNKNOW_DEVICE,      },
    { macEdfeForceStop,                wsmac_spinel_set_bool,                  SPINEL_PROP_WS_EDFE_FORCE_STOP,                  },
    { macAssociationPermit,            wsmac_spinel_set_bool,                  SPINEL_PROP_WS_ASSOCIATION_PERMIT,               },
    { phyCurrentChannel,               wsmac_spinel_set_u8,                    SPINEL_PROP_PHY_CHAN,                            },
    { macAutoRequestKeyIdMode,         wsmac_spinel_set_u8,                    SPINEL_PROP_WS_AUTO_REQUEST_KEY_ID_MODE,         },
    { macAutoRequestKeyIndex,          wsmac_spinel_set_u8,                    SPINEL_PROP_WS_AUTO_REQUEST_KEY_INDEX,           },
    { macAutoRequestSecurityLevel,     wsmac_spinel_set_u8,                    SPINEL_PROP_WS_AUTO_REQUEST_SECURITY_LEVEL,      },
    { macBeaconPayloadLength,          wsmac_spinel_set_u8,                    SPINEL_PROP_WS_BEACON_PAYLOAD_LENGTH,            },
    { macMaxFrameRetries,              wsmac_spinel_set_u8,                    SPINEL_PROP_WS_MAX_FRAME_RETRIES,                },
    { macTXPower,                      wsmac_spinel_set_u8,                    SPINEL_PROP_PHY_TX_POWER,                        },
    { macMaxCSMABackoffs,              wsmac_spinel_set_u8,                    SPINEL_PROP_WS_MAX_CSMA_BACKOFFS,                },
    { macMinBE,                        wsmac_spinel_set_u8,                    SPINEL_PROP_WS_MIN_BE,                           },
    { macMaxBE,                        wsmac_spinel_set_u8,                    SPINEL_PROP_WS_MAX_BE,                           },
    { macCCAThreshold,                 wsmac_spinel_set_u8,                    SPINEL_PROP_WS_CCA_THRESHOLD,                    },
    { macPANId,                        wsmac_spinel_set_u16,                   SPINEL_PROP_MAC_15_4_PANID,                      },
    { macCoordShortAddress,            wsmac_spinel_set_u16,                   SPINEL_PROP_WS_COORD_SHORT_ADDRESS,              },
    { macShortAddress,                 wsmac_spinel_set_u16,                   SPINEL_PROP_MAC_15_4_SADDR,                      },
    { macDeviceDescriptionPanIDUpdate, wsmac_spinel_set_u16,                   SPINEL_PROP_WS_DEVICE_DESCRIPTION_PAN_ID_UPDATE, },
    { macAckWaitDuration,              wsmac_spinel_set_u16,                   SPINEL_PROP_WS_ACK_WAIT_DURATION,                },
    { mac802_15_4Mode,                 wsmac_spinel_set_u32,                   SPINEL_PROP_WS_15_4_MODE,                        },
    { macAutoRequestKeySource,         wsmac_spinel_set_eui64,                 SPINEL_PROP_WS_AUTO_REQUEST_KEY_SOURCE,          },
    { macCoordExtendedAddress,         wsmac_spinel_set_eui64,                 SPINEL_PROP_WS_COORD_EXTENDED_ADDRESS,           },
    { macDefaultKeySource,             wsmac_spinel_set_eui64,                 SPINEL_PROP_WS_DEFAULT_KEY_SOURCE,               },
    { macBeaconPayload,                wsmac_spinel_set_data,                  SPINEL_PROP_WS_BEACON_PAYLOAD,                   },
    { macCCAThresholdStart,            wsmac_spinel_set_cca_threshold_start,   SPINEL_PROP_WS_CCA_THRESHOLD_START,              },
    { macMultiCSMAParameters,          wsmac_spinel_set_multi_csma_parameters, SPINEL_PROP_WS_MULTI_CSMA_PARAMETERS,            },
    { macRfConfiguration,              wsmac_spinel_set_rf_configuration,      SPINEL_PROP_WS_RF_CONFIGURATION,                 },
    { macDeviceTable,                  wsmac_spinel_set_device_table,          SPINEL_PROP_WS_DEVICE_TABLE,                     },
    { macKeyTable,                     wsmac_spinel_set_key_table,             SPINEL_PROP_WS_KEY_TABLE,                        },
    { macFrameCounter,                 wsmac_spinel_set_frame_counter,         SPINEL_PROP_WS_FRAME_COUNTER,                    },
    { macRequestRestart,               wsmac_spinel_set_request_restart,       SPINEL_PROP_WS_REQUEST_RESTART,                  },
    { 0 /* Special */,                 wsmac_spinel_set_frame_counter_per_key, SPINEL_PROP_WS_ENABLE_FRAME_COUNTER_PER_KEY,     },
    { 0 /* Special */,                 wsmac_spinel_fhss_create,               SPINEL_PROP_WS_FHSS_CREATE,                      },
    { 0 /* Special */,                 wsmac_spinel_fhss_delete,               SPINEL_PROP_WS_FHSS_DELETE,                      },
    { 0 /* Special */,                 wsmac_spinel_fhss_register,             SPINEL_PROP_WS_FHSS_REGISTER,                    },
    { 0 /* Special */,                 wsmac_spinel_fhss_unregister,           SPINEL_PROP_WS_FHSS_UNREGISTER,                  },
    { 0 /* Special */,                 wsmac_spinel_fhss_set_hop_count,        SPINEL_PROP_WS_FHSS_SET_HOP_COUNT,               },
    { 0 /* Special */,                 wsmac_spinel_fhss_set_conf,             SPINEL_PROP_WS_FHSS_SET_CONF,                    },
    { 0 /* Special */,                 wsmac_spinel_fhss_set_parent,           SPINEL_PROP_WS_FHSS_SET_PARENT,                  },
    { 0 /* Special */,                 wsmac_spinel_fhss_update_neighbor,      SPINEL_PROP_WS_FHSS_UPDATE_NEIGHBOR,             },
    { 0 /* Special */,                 wsmac_spinel_fhss_drop_neighbor,        SPINEL_PROP_WS_FHSS_DROP_NEIGHBOR,               },
    { 0 /* Special */,                 wsmac_spinel_fhss_set_tx_allowance_level, SPINEL_PROP_WS_FHSS_SET_TX_ALLOWANCE_LEVEL,    },
    { 0 /* Special */,                 wsmac_spinel_ws_start,                  SPINEL_PROP_WS_START,                            },
    { 0 /* Special */,                 wsmac_spinel_ws_reset,                  SPINEL_PROP_WS_RESET,                            },
    { 0 /* Special */,                 wsmac_spinel_data_req,                  SPINEL_PROP_STREAM_RAW,                          },
    { }
};

#define SPINEL_SIZE_MAX (MAC_IEEE_802_15_4G_MAX_PHY_PACKET_SIZE + 70)

// Warning, no re-entrancy for any of indications or confirmations.
struct {
    struct spinel_buffer s;
    char b[SPINEL_SIZE_MAX];
} __tx_buf = {
    .s.len = SPINEL_SIZE_MAX,
};
static struct spinel_buffer *tx_buf = (struct spinel_buffer *)&__tx_buf;

// Warning, no re-entrancy for wsmac_rx_host().
struct {
    struct spinel_buffer s;
    char b[SPINEL_SIZE_MAX];
} __rx_buf = {
    .s.len = SPINEL_SIZE_MAX,
};
static struct spinel_buffer *rx_buf = (struct spinel_buffer *)&__rx_buf;

void spinel_push_hdr_is_prop(struct wsmac_ctxt *ctxt, struct spinel_buffer *buf, unsigned int prop)
{
    spinel_push_u8(buf, wsbr_get_spinel_hdr(ctxt));
    spinel_push_int(buf, SPINEL_CMD_PROP_VALUE_IS);
    spinel_push_int(buf, prop);
}

static void wsmac_spinel_get_hw_addr(struct wsmac_ctxt *ctxt)
{
    spinel_reset(tx_buf);
    spinel_push_hdr_is_prop(ctxt, tx_buf, SPINEL_PROP_HWADDR);
    spinel_push_fixed_u8_array(tx_buf, ctxt->eui64, 8);
    uart_tx(ctxt->os_ctxt, tx_buf->frame, tx_buf->cnt);
}

void wsmac_rx_host(struct wsmac_ctxt *ctxt)
{
    int cmd, prop;
    int i;

    rx_buf->len = uart_rx(ctxt->os_ctxt, rx_buf->frame, SPINEL_SIZE_MAX);
    if (!rx_buf->len)
        return;
    spinel_reset(rx_buf);
    spinel_pop_u8(rx_buf); /* packet header */
    cmd = spinel_pop_int(rx_buf);
    if (cmd == SPINEL_CMD_PROP_VALUE_GET || cmd == SPINEL_CMD_PROP_VALUE_SET) {
        prop = spinel_pop_int(rx_buf);
        for (i = 0; mlme_prop_cstr[i].prop; i++)
            if (prop == mlme_prop_cstr[i].prop)
                break;
    }

    if (cmd == SPINEL_CMD_RESET) {
        mlme_reset_t req = {
            .SetDefaultPIB = true,
        };

        BUG_ON(spinel_remaining_size(rx_buf));
        ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_RESET, &req);
        ns_sw_mac_fhss_unregister(ctxt->rcp_mac_api);
        ns_fhss_delete(ctxt->fhss_api);
        ctxt->fhss_api = NULL;
        wsmac_reset_ind(ctxt, false);
    } else if (cmd == SPINEL_CMD_PROP_VALUE_GET && prop == SPINEL_PROP_HWADDR) {
        int index = spinel_pop_int(rx_buf);

        WARN_ON(index != 0);
        BUG_ON(spinel_remaining_size(rx_buf));
        wsmac_spinel_get_hw_addr(ctxt);
    } else if (cmd == SPINEL_CMD_PROP_VALUE_GET) {
        int index = spinel_pop_int(rx_buf);
        mlme_get_t req = {
            .attr_index = index,
            .attr = mlme_prop_cstr[i].attr,
        };

        BUG_ON(spinel_remaining_size(rx_buf));
        ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_GET, &req);
    } else if (cmd == SPINEL_CMD_PROP_VALUE_SET) {
        if (mlme_prop_cstr[i].prop_set)
            mlme_prop_cstr[i].prop_set(ctxt, mlme_prop_cstr[i].attr, rx_buf);
        else
            WARN("property not implemented: %08x", prop);
    } else {
        WARN("not implemented");
        return;
    }
}

void wsmac_mlme_get(struct wsmac_ctxt *ctxt, const void *data)
{
    const mlme_get_conf_t *req = data;

    switch (req->attr) {
    case macDeviceTable: {
        const mlme_device_descriptor_t *descr = req->value_pointer;

        BUG_ON(req->value_size != sizeof(mlme_device_descriptor_t));
        spinel_reset(tx_buf);
        spinel_push_hdr_is_prop(ctxt, tx_buf, SPINEL_PROP_WS_DEVICE_TABLE);
        spinel_push_int(tx_buf,  req->attr_index);
        spinel_push_u16(tx_buf,  descr->PANId);
        spinel_push_u16(tx_buf,  descr->ShortAddress);
        spinel_push_fixed_u8_array(tx_buf, descr->ExtAddress, 8);
        spinel_push_u32(tx_buf,  descr->FrameCounter);
        spinel_push_bool(tx_buf, descr->Exempt);
        uart_tx(ctxt->os_ctxt, tx_buf->frame, tx_buf->cnt);
        break;
    }
    case macFrameCounter: {
        const uint32_t *descr = req->value_pointer;

        BUG_ON(req->value_size != sizeof(uint32_t));
        //BUG_ON(req->attr_index != XXXsecurity_frame_counter);
        spinel_reset(tx_buf);
        spinel_push_hdr_is_prop(ctxt, tx_buf, SPINEL_PROP_WS_FRAME_COUNTER);
        spinel_push_int(tx_buf, req->attr_index);
        spinel_push_u32(tx_buf, *descr);
        uart_tx(ctxt->os_ctxt, tx_buf->frame, tx_buf->cnt);
        break;
    }
    case macCCAThreshold: {
        BUG_ON(req->value_size > 200);
        spinel_reset(tx_buf);
        spinel_push_hdr_is_prop(ctxt, tx_buf, SPINEL_PROP_WS_CCA_THRESHOLD);
        spinel_push_data(tx_buf, req->value_pointer, req->value_size);
        uart_tx(ctxt->os_ctxt, tx_buf->frame, tx_buf->cnt);
        break;
    }
    default:
        WARN("not implemented");
        break;
    }
}

void wsmac_mlme_start(struct wsmac_ctxt *ctxt, const void *data)
{
    const mlme_start_conf_t *req = data;

    WARN_ON(req->status);
    spinel_reset(tx_buf);
    spinel_push_hdr_is_prop(ctxt, tx_buf, SPINEL_PROP_LAST_STATUS);
    spinel_push_int(tx_buf, SPINEL_STATUS_OK);
    uart_tx(ctxt->os_ctxt, tx_buf->frame, tx_buf->cnt);
}

void wsmac_mlme_scan(struct wsmac_ctxt *ctxt, const void *data)
{
    //const mlme_scan_conf_t *req = data;

    WARN("not implemented");
}

void wsmac_mlme_confirm(const mac_api_t *mac_api, mlme_primitive id, const void *data)
{
    struct wsmac_ctxt *ctxt = &g_ctxt;
    static const struct {
        int id;
        void (*fn)(struct wsmac_ctxt *, const void *);
    } table[] = {
        { MLME_GET,   wsmac_mlme_get },
        { MLME_START, wsmac_mlme_start },
        { MLME_SCAN,  wsmac_mlme_scan },
        { -1,         NULL },
    };
    int i;

    BUG_ON(!mac_api);
    BUG_ON(ctxt->rcp_mac_api != mac_api);
    for (i = 0; table[i].id != -1; i++)
        if (id == table[i].id)
            break;
    if (!table[i].fn) {
        WARN("not implemented");
        return;
    }
    table[i].fn(ctxt, data);
}

void wsmac_mcps_data_confirm_ext(const mac_api_t *mac_api, const mcps_data_conf_t *data,
                                 const mcps_data_conf_payload_t *conf_data)
{
    struct msdu_malloc_info *malloc_info;
    struct wsmac_ctxt *ctxt = &g_ctxt;

    BUG_ON(!mac_api);
    BUG_ON(mac_api != ctxt->rcp_mac_api);
    BUG_ON(!conf_data, "not implemented");

    spinel_reset(tx_buf);
    spinel_push_hdr_is_prop(ctxt, tx_buf, SPINEL_PROP_STREAM_STATUS);
    spinel_push_u8(tx_buf,   data->status);
    spinel_push_u8(tx_buf,   data->msduHandle);
    spinel_push_u32(tx_buf,  data->timestamp);
    spinel_push_u8(tx_buf,   data->cca_retries);
    spinel_push_u8(tx_buf,   data->tx_retries);
    spinel_push_data(tx_buf, conf_data->headerIeList, conf_data->headerIeListLength);
    spinel_push_data(tx_buf, conf_data->payloadIeList, conf_data->headerIeListLength);
    spinel_push_data(tx_buf, conf_data->payloadPtr, conf_data->payloadLength);
    uart_tx(ctxt->os_ctxt, tx_buf->frame, tx_buf->cnt);

    malloc_info = SLIST_REMOVE(ctxt->msdu_malloc_list, malloc_info,
                               list, malloc_info->msduHandle == data->msduHandle);
    BUG_ON(!malloc_info);
    free(malloc_info->header->ieBase);
    free(malloc_info->payload->ieBase);
    free(malloc_info->header);
    free(malloc_info->payload);
    free(malloc_info->msdu);
    free(malloc_info);
}

void wsmac_mcps_data_confirm(const mac_api_t *mac_api, const mcps_data_conf_t *data)
{
    wsmac_mcps_data_confirm_ext(mac_api, data, NULL);
}

void wsmac_mcps_data_indication_ext(const mac_api_t *mac_api, const mcps_data_ind_t *data,
                                    const mcps_data_ie_list_t *ie_ext)
{
    struct wsmac_ctxt *ctxt = &g_ctxt;

    BUG_ON(!mac_api);
    BUG_ON(mac_api != ctxt->rcp_mac_api);
    BUG_ON(!ie_ext, "not implemented");

    spinel_reset(tx_buf);
    spinel_push_hdr_is_prop(ctxt, tx_buf, SPINEL_PROP_STREAM_RAW);
    spinel_push_data(tx_buf, data->msdu_ptr, data->msduLength);
    spinel_push_u8(tx_buf,   data->SrcAddrMode);
    spinel_push_u16(tx_buf,  data->SrcPANId);
    spinel_push_fixed_u8_array(tx_buf, data->SrcAddr, 8);
    spinel_push_u8(tx_buf,   data->DstAddrMode);
    spinel_push_u16(tx_buf,  data->DstPANId);
    spinel_push_fixed_u8_array(tx_buf, data->DstAddr, 8);
    spinel_push_u8(tx_buf,   data->mpduLinkQuality);
    spinel_push_i8(tx_buf,   data->signal_dbm);
    spinel_push_u32(tx_buf,  data->timestamp);
    spinel_push_bool(tx_buf, data->DSN_suppressed);
    spinel_push_u8(tx_buf,   data->DSN);
    spinel_push_u8(tx_buf,   data->Key.SecurityLevel);
    spinel_push_u8(tx_buf,   data->Key.KeyIdMode);
    spinel_push_u8(tx_buf,   data->Key.KeyIndex);
    spinel_push_fixed_u8_array(tx_buf, data->Key.Keysource, 8);
    spinel_push_data(tx_buf, ie_ext->headerIeList, ie_ext->headerIeListLength);
    spinel_push_data(tx_buf, ie_ext->payloadIeList, ie_ext->payloadIeListLength);
    uart_tx(ctxt->os_ctxt, tx_buf->frame, tx_buf->cnt);
}

void wsmac_mcps_data_indication(const mac_api_t *mac_api, const mcps_data_ind_t *data)
{
    wsmac_mcps_data_indication_ext(mac_api, data, NULL);
}


void wsmac_mcps_purge_confirm(const mac_api_t *mac_api, mcps_purge_conf_t *data)
{
    WARN("not implemented");
}

void wsmac_mlme_indication(const mac_api_t *mac_api, mlme_primitive id, const void *data)
{
    struct wsmac_ctxt *ctxt = &g_ctxt;
    int data_len;

    BUG_ON(!mac_api);
    BUG_ON(mac_api != ctxt->rcp_mac_api);
    switch (id) {
        case MLME_BEACON_NOTIFY: {
            // data_len = sizeof(mlme_beacon_ind_t);
            DEBUG("dataInd MLME_BEACON_NOTIFY indication not yet supported");
            break;
        }
        case MLME_COMM_STATUS: {
            DEBUG("dataInd MLME_COMM_STATUS");
            data_len = sizeof(mlme_comm_status_t);
            break;
        }
        case MLME_SYNC_LOSS: {
            DEBUG("dataInd MLME_SYNC_LOSS");
            data_len = sizeof(mlme_sync_loss_t);
            break;
        }
        default: {
            DEBUG("dataInd MLME indication ignored");
            data_len = 0;
        }
    }

    spinel_reset(tx_buf);
    spinel_push_hdr_is_prop(ctxt, tx_buf, SPINEL_PROP_WS_MLME_IND);
    spinel_push_int(tx_buf, id);
    spinel_push_data(tx_buf, data, data_len);
    uart_tx(ctxt->os_ctxt, tx_buf->frame, tx_buf->cnt);
}

// Copy-paste from nanostack/source/6LoWPAN/MAC/mac_ie_lib.c
#define MAC_IE_HEADER_LENGTH_MASK 0x007f
#define MAC_IE_HEADER_ID_MASK     0x7f80

// Copy-paste from mbed-client-libservice/mbed-client-libservice/common_functions.h
static uint8_t *common_write_16_bit_inverse(uint16_t value, uint8_t ptr[static 2])
{
    *ptr++ = value;
    *ptr++ = value >> 8;
    return ptr;
}

// Copy-paste from nanostack/source/6LoWPAN/ws/ws_neighbor_class.c
static uint8_t ws_neighbor_class_rsl_from_dbm_calculate(int8_t dbm_heard)
{
    /* RSL MUST be calculated as the received signal level relative to standard
     * thermal noise (290oK) at 1 Hz bandwidth or 174 dBm.
     * This provides a range of -174 (0) to +80 (254) dBm.
     */

    return dbm_heard + 174;
}

// Copy-paste from nanostack/source/6LoWPAN/MAC/mac_ie_lib.c
static uint8_t *mac_ie_header_base_write(uint8_t *ptr, uint8_t type, uint16_t length)
{
    uint16_t ie_dummy = 0; //Header Type
    ie_dummy |= (length & MAC_IE_HEADER_LENGTH_MASK);
    ie_dummy |= ((type << 7) &  MAC_IE_HEADER_ID_MASK);
    return common_write_16_bit_inverse(ie_dummy, ptr);
}

// Copy-paste from nanostack/source/6LoWPAN/ws/ws_ie_lib.c
static uint8_t *ws_wh_header_base_write(uint8_t *ptr, uint16_t length, uint8_t type)
{
    ptr = mac_ie_header_base_write(ptr, MAC_HEADER_ASSIGNED_EXTERNAL_ORG_IE_ID, length + 1);
    *ptr++ = type;
    return ptr;
}

// Copy-paste from nanostack/source/6LoWPAN/ws/ws_ie_lib.c
static uint8_t *ws_wh_utt_write(uint8_t *ptr, uint8_t message_type)
{
    ptr = ws_wh_header_base_write(ptr, 4, WH_IE_UTT_TYPE);
    *ptr++ = message_type;
    memset(ptr, 0, 3);
    ptr += 3;
    return ptr;
}

// Copy-paste from nanostack/source/6LoWPAN/ws/ws_ie_lib.c
static uint8_t *ws_wh_rsl_write(uint8_t *ptr, uint8_t rsl)
{
    ptr = ws_wh_header_base_write(ptr, 1, WH_IE_RSL_TYPE);
    *ptr++ = rsl;
    return ptr;
}

// Inspired from ws_llc_ack_data_req_ext() from nanostack/source/6LoWPAN/ws/ws_llc_data_service.c
void wsmac_mcps_ack_data_req_ext(const mac_api_t *mac_api, mcps_ack_data_payload_t *data,
                                 int8_t rssi, uint8_t lqi)
{
    // It is safe to use static buffer. Indeed, result of this function is
    // always stored in enhanced_ack_buffer that is instanciated only once for
    // each MAC.
    static ns_ie_iovec_t header_vector;
    static uint8_t ie[20];

    DEBUG("ackDataReq");
    memset(data, 0, sizeof(mcps_ack_data_payload_t));
    data->ie_elements.headerIovLength = 1;
    data->ie_elements.headerIeVectorList = &header_vector;
    data->ie_elements.headerIeVectorList->ieBase = ie;

    // Write Data to block
    uint8_t *ptr = ie;
    ptr = ws_wh_utt_write(ptr, WS_FT_ACK);
    ptr = ws_wh_rsl_write(ptr, ws_neighbor_class_rsl_from_dbm_calculate(rssi));
    data->ie_elements.headerIeVectorList->iovLen = ptr - ie;
}

void wsmac_mcps_edfe_handler(const mac_api_t *mac_api, mcps_edfe_response_t *response_message)
{
    WARN("not implemented");
}

void wsmac_reset_ind(struct wsmac_ctxt *ctxt, bool hw)
{
    spinel_reset(tx_buf);
    spinel_push_u8(tx_buf, wsbr_get_spinel_hdr(ctxt));
    spinel_push_int(tx_buf, SPINEL_CMD_RESET);
    spinel_push_u32(tx_buf, version_api);
    spinel_push_u32(tx_buf, version_fw);
    spinel_push_str(tx_buf, version_fw_str);
    spinel_push_bool(tx_buf, hw);
    spinel_push_u8(tx_buf, g_storage_sizes.device_decription_table_size);
    spinel_push_u8(tx_buf, g_storage_sizes.key_description_table_size);
    spinel_push_u8(tx_buf, g_storage_sizes.key_lookup_size);
    spinel_push_u8(tx_buf, g_storage_sizes.key_usage_size);

    // Further bytes reserved for RF parameters
    spinel_push_u32(tx_buf, 0);
    spinel_push_u32(tx_buf, 0);
    spinel_push_u8(tx_buf, 0);
    spinel_push_u8(tx_buf, 0);
    spinel_push_u8(tx_buf, 0);
    uart_tx(ctxt->os_ctxt, tx_buf->frame, tx_buf->cnt);
}
