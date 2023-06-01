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
#include "stack/mac/channel_list.h"
#include "stack/mac/mlme.h"
#include "stack/mac/mac_mcps.h"
#include "stack/mac/sw_mac.h"
#include "stack/mac/fhss_api.h"
#include "stack/mac/fhss_config.h"
#include "stack/mac/net_fhss.h"

#include "version.h"
#include "sl_wsrcp.h"
#include "sl_wsrcp_mac.h"
#include "hal_fhss_timer.h"
#include "common/bus_uart.h"
#include "common/endian.h"
#include "common/spinel_defs.h"
#include "common/spinel_buffer.h"
#include "common/utils.h"
#include "common/iobuf.h"
#include "common/bits.h"
#include "common/log.h"

static void wsmac_rf_status_ind(struct wsmac_ctxt *ctxt, int status);
static void wsmac_spinel_get_rf_configs(struct wsmac_ctxt *ctxt);

static uint8_t wsbr_get_spinel_hdr(struct wsmac_ctxt *ctxt)
{
    uint8_t hdr = FIELD_PREP(0xC0, 0x2) | FIELD_PREP(0x30, ctxt->spinel_iid);

    ctxt->spinel_tid = (ctxt->spinel_tid + 1) % 0x10;
    if (!ctxt->spinel_tid)
        ctxt->spinel_tid = 1;
    hdr |= FIELD_PREP(0x0F, ctxt->spinel_tid);
    return hdr;
}

static void wsmac_spinel_set_bool(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    bool data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };

    data = spinel_pop_bool(buf);
    BUG_ON(iobuf_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_u8(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    uint8_t data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };

    data = spinel_pop_u8(buf);
    BUG_ON(iobuf_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_u16(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    uint16_t data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };

    data = spinel_pop_u16(buf);
    BUG_ON(iobuf_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_u32(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    uint32_t data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };

    data = spinel_pop_u32(buf);
    BUG_ON(iobuf_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_eui64(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    uint8_t data[8];
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = data,
        .value_size = sizeof(data),
    };

    spinel_pop_fixed_u8_array(buf, data, 8);
    BUG_ON(iobuf_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_cca_threshold_start(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    uint8_t data[4];
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = data,
        .value_size = sizeof(data),
    };

    spinel_pop_fixed_u8_array(buf, data, 4);
    BUG_ON(iobuf_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_rf_configuration(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    struct phy_rf_channel_configuration data;
    int ret;
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
    if (iobuf_remaining_size(buf)) {
        spinel_pop_bool(buf); // fec
        spinel_pop_uint(buf); // ofdm_option
        spinel_pop_uint(buf); // ofdm_mcs
    }
    BUG_ON(iobuf_remaining_size(buf));
    ret = ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
    wsmac_rf_status_ind(ctxt, ret);
}

static void wsmac_spinel_set_device_table(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    struct mlme_device_descriptor data;
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
    BUG_ON(iobuf_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_key_table(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
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
    BUG_ON(iobuf_remaining_size(buf));
    if (lookup_len) {
        data.KeyIdLookupListEntries = 1;
        if (lookup_len == 9)
            data.KeyIdLookupList->LookupDataSize = 1;
        else
            BUG_ON(lookup_len != 5);
    }
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_request_restart(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
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
    BUG_ON(iobuf_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_frame_counter(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    uint32_t data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };

    BUG_ON(attr != macFrameCounter);
    req.attr_index = spinel_pop_uint(buf);
    data           = spinel_pop_u32(buf);
    BUG_ON(iobuf_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_fhss_set_parent(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    struct fhss_ws_neighbor_timing_info timing;
    uint8_t eui64[8];
    bool force_synch;

    spinel_pop_fixed_u8_array(buf, eui64, 8);
    force_synch                      = spinel_pop_bool(buf);
    timing.bc_chan_func              = spinel_pop_u8(buf);
    timing.ffn.bc_dwell_interval_ms  = spinel_pop_u8(buf);
    timing.bc_chan_fixed             = spinel_pop_u16(buf);
    timing.ffn.bc_slot               = spinel_pop_u16(buf);
    timing.ffn.bsi                   = spinel_pop_u16(buf);
    timing.ffn.bc_interval_offset_ms = spinel_pop_u32(buf);
    timing.ffn.bc_interval_ms        = spinel_pop_u32(buf);
    timing.ffn.bt_rx_tstamp_us       = spinel_pop_u32(buf);
    BUG_ON(iobuf_remaining_size(buf));
    ns_fhss_ws_set_parent(ctxt->fhss_api, eui64, &timing, force_synch);
}

static void wsmac_spinel_set_frame_counter_per_key(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    bool data;

    data = spinel_pop_bool(buf);
    BUG_ON(iobuf_remaining_size(buf));
    ns_sw_mac_enable_frame_counter_per_key(ctxt->rcp_mac_api, data);
}

static void wsmac_spinel_fhss_set_tx_allowance_level(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    int global_level, ef_level;

    global_level = spinel_pop_uint(buf);
    ef_level     = spinel_pop_uint(buf);
    BUG_ON(iobuf_remaining_size(buf));
    ns_fhss_ws_set_tx_allowance_level(ctxt->fhss_api, global_level, ef_level);
}

static void wsmac_spinel_fhss_update_neighbor(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
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

    fhss_data->clock_drift                   = spinel_pop_u8(buf);
    fhss_data->timing_accuracy               = spinel_pop_u8(buf);
    fhss_data->uc_channel_list.channel_count = spinel_pop_u16(buf);
    spinel_pop_fixed_u8_array(buf, fhss_data->uc_channel_list.channel_mask, 32);
    fhss_data->uc_chan_func                  = spinel_pop_u8(buf);
    fhss_data->ffn.uc_dwell_interval_ms      = spinel_pop_u8(buf);
    fhss_data->uc_chan_count                 = spinel_pop_u16(buf);
    fhss_data->uc_chan_fixed                 = spinel_pop_u16(buf);
    fhss_data->ffn.ufsi                      = spinel_pop_u32(buf);
    fhss_data->ffn.utt_rx_tstamp_us          = spinel_pop_u32(buf);
    BUG_ON(iobuf_remaining_size(buf));
}

static void wsmac_spinel_fhss_drop_neighbor(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
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

static void wsmac_spinel_fhss_create(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
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
    spinel_pop_fixed_u8_array(buf, config.domain_channel_mask, 32);
    spinel_pop_fixed_u8_array(buf, config.unicast_channel_mask, 32);
    config.channel_mask_size       = spinel_pop_u16(buf);
    config.config_parameters.number_of_channel_retries = spinel_pop_u8(buf);
    if (iobuf_remaining_size(buf))
        spinel_pop_fixed_u8_array(buf, config.broadcast_channel_mask, 32);
    BUG_ON(iobuf_remaining_size(buf));
    ctxt->fhss_api = ns_fhss_ws_create(&config, &wsmac_fhss);
    BUG_ON(!ctxt->fhss_api);
    ns_fhss_set_neighbor_info_fp(ctxt->fhss_api, wsmac_fhss_get_neighbor_info);
}

static void wsmac_spinel_fhss_delete(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    BUG_ON(iobuf_remaining_size(buf));
    ns_fhss_delete(ctxt->fhss_api);
    ctxt->fhss_api = NULL;
}

static void wsmac_spinel_fhss_set_conf(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
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
    spinel_pop_fixed_u8_array(buf, config.domain_channel_mask, 32);
    spinel_pop_fixed_u8_array(buf, config.unicast_channel_mask, 32);
    config.channel_mask_size       = spinel_pop_u16(buf);
    config.config_parameters.number_of_channel_retries = spinel_pop_u8(buf);
    if (iobuf_remaining_size(buf))
        spinel_pop_fixed_u8_array(buf, config.broadcast_channel_mask, 32);
    BUG_ON(iobuf_remaining_size(buf));
    ns_fhss_ws_configuration_set(ctxt->fhss_api, &config);
}

static void wsmac_spinel_fhss_set_hop_count(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    uint8_t data;

    data = spinel_pop_u8(buf);
    BUG_ON(iobuf_remaining_size(buf));
    ns_fhss_ws_set_hop_count(ctxt->fhss_api, data);
}

static void wsmac_spinel_fhss_register(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    struct fhss_api *fhss_api = ns_sw_mac_get_fhss_api(ctxt->rcp_mac_api);

    BUG_ON(iobuf_remaining_size(buf));
    BUG_ON(fhss_api, "fhss_api already regstered");
    BUG_ON(!ctxt->fhss_api, "fhss_api not yet created");
    ns_sw_mac_fhss_register(ctxt->rcp_mac_api, ctxt->fhss_api);
}

static void wsmac_spinel_fhss_unregister(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    struct fhss_api *fhss_api = ns_sw_mac_get_fhss_api(ctxt->rcp_mac_api);

    BUG_ON(iobuf_remaining_size(buf));
    BUG_ON(fhss_api != ctxt->fhss_api);
    ns_sw_mac_fhss_unregister(ctxt->rcp_mac_api);
    ctxt->fhss_api = NULL;
}

static void wsmac_spinel_ws_start(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    mlme_start_t req = { };

    req.PANId           = spinel_pop_u16(buf);
    req.LogicalChannel  = spinel_pop_u8(buf);
    req.ChannelPage     = spinel_pop_u8(buf);
    req.StartTime       = spinel_pop_u32(buf);
    req.BeaconOrder     = spinel_pop_u8(buf);
    req.SuperframeOrder = spinel_pop_u8(buf);
    req.PANCoordinator  = spinel_pop_bool(buf);
    BUG_ON(iobuf_remaining_size(buf));
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_START, &req);
}

static void wsmac_spinel_ws_reset(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    mlme_reset_t req = { };

    req.SetDefaultPIB = spinel_pop_bool(buf);
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_RESET, &req);
}

static void wsmac_spinel_data_req(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    struct mcps_data_req data;
    struct mcps_data_req_ie_list ie_ext = { };
    struct channel_list async_channel_list;
    struct msdu_malloc_info *malloc_info;
    const uint8_t *ptr;
    uint16_t prio;
    int len;

    data.msduLength                 = spinel_pop_data_ptr(buf, &ptr);
    data.msdu = malloc(data.msduLength);
    memcpy(data.msdu, ptr, data.msduLength);
    data.SrcAddrMode                = spinel_pop_u8(buf);
    data.DstAddrMode                = spinel_pop_u8(buf);
    data.DstPANId                   = spinel_pop_u16(buf);
    spinel_pop_fixed_u8_array(buf, data.DstAddr, 8);
    data.msduHandle                 = spinel_pop_u8(buf);
    data.TxAckReq                   = spinel_pop_bool(buf);
    spinel_pop_bool(buf); // formerly InDirectTx
    data.PendingBit                 = spinel_pop_bool(buf);
    data.SeqNumSuppressed           = spinel_pop_bool(buf);
    data.PanIdSuppressed            = spinel_pop_bool(buf);
    data.ExtendedFrameExchange      = spinel_pop_bool(buf);
    data.Key.SecurityLevel          = spinel_pop_u8(buf);
    data.Key.KeyIdMode              = spinel_pop_u8(buf);
    data.Key.KeyIndex               = spinel_pop_u8(buf);
    spinel_pop_fixed_u8_array(buf, data.Key.Keysource, 8);
    prio                            = spinel_pop_u16(buf);
    async_channel_list.channel_page = spinel_pop_uint(buf);
    spinel_pop_fixed_u8_array(buf, async_channel_list.channel_mask, 32);

    len = spinel_pop_data_ptr(buf, &ptr);
    if (len) {
        ie_ext.payloadIovLength = 1;
        ie_ext.payloadIeVectorList = malloc(sizeof(struct iovec));
        ie_ext.payloadIeVectorList->iov_len = len;
        ie_ext.payloadIeVectorList->iov_base = malloc(len);
        memcpy(ie_ext.payloadIeVectorList->iov_base, ptr, len);
    }

    len = spinel_pop_data_ptr(buf, &ptr);
    if (len) {
        ie_ext.headerIovLength = 1;
        ie_ext.headerIeVectorList = malloc(sizeof(struct iovec));
        ie_ext.headerIeVectorList->iov_len = len;
        ie_ext.headerIeVectorList->iov_base = malloc(len);
        memcpy(ie_ext.headerIeVectorList->iov_base, ptr, len);
    }
    if (iobuf_remaining_size(buf))
         async_channel_list.next_channel_number = spinel_pop_u16(buf);
    else
         async_channel_list.next_channel_number = 0;
    if (iobuf_remaining_size(buf))
         spinel_pop_u8(buf); // phy_id
    BUG_ON(iobuf_remaining_size(buf));

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

static void wsmac_spinel_ws_mcps_drop(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf)
{
    struct mcps_purge data = { 0 };

    (void)attr;
    data.msduHandle = spinel_pop_u8(buf);
    BUG_ON(iobuf_remaining_size(buf));
    ctxt->rcp_mac_api->mcps_purge_req(ctxt->rcp_mac_api, &data);
}

static const struct {
    mlme_attr_e attr;
    void (*prop_set)(struct wsmac_ctxt *ctxt, mlme_attr_e attr, struct iobuf_read *buf);
    unsigned int prop;
} mlme_prop_cstr[] = {
    { macRxOnWhenIdle,                 wsmac_spinel_set_bool,                  SPINEL_PROP_WS_RX_ON_WHEN_IDLE,                  },
    { macSecurityEnabled,              wsmac_spinel_set_bool,                  SPINEL_PROP_WS_SECURITY_ENABLED,                 },
    { macAcceptByPassUnknowDevice,     wsmac_spinel_set_bool,                  SPINEL_PROP_WS_ACCEPT_BYPASS_UNKNOW_DEVICE,      },
    { macEdfeForceStop,                wsmac_spinel_set_bool,                  SPINEL_PROP_WS_EDFE_FORCE_STOP,                  },
    { phyCurrentChannel,               wsmac_spinel_set_u8,                    SPINEL_PROP_PHY_CHAN,                            },
    { macAutoRequestKeyIdMode,         wsmac_spinel_set_u8,                    SPINEL_PROP_WS_AUTO_REQUEST_KEY_ID_MODE,         },
    { macAutoRequestKeyIndex,          wsmac_spinel_set_u8,                    SPINEL_PROP_WS_AUTO_REQUEST_KEY_INDEX,           },
    { macAutoRequestSecurityLevel,     wsmac_spinel_set_u8,                    SPINEL_PROP_WS_AUTO_REQUEST_SECURITY_LEVEL,      },
    { macMaxFrameRetries,              wsmac_spinel_set_u8,                    SPINEL_PROP_WS_MAX_FRAME_RETRIES,                },
    { macTXPower,                      wsmac_spinel_set_u8,                    SPINEL_PROP_PHY_TX_POWER,                        },
    { macMaxCSMABackoffs,              wsmac_spinel_set_u8,                    SPINEL_PROP_WS_MAX_CSMA_BACKOFFS,                },
    { macMinBE,                        wsmac_spinel_set_u8,                    SPINEL_PROP_WS_MIN_BE,                           },
    { macMaxBE,                        wsmac_spinel_set_u8,                    SPINEL_PROP_WS_MAX_BE,                           },
    { macCCAThreshold,                 wsmac_spinel_set_u8,                    SPINEL_PROP_WS_CCA_THRESHOLD,                    },
    { macPANId,                        wsmac_spinel_set_u16,                   SPINEL_PROP_MAC_15_4_PANID,                      },
    { macCoordShortAddress,            wsmac_spinel_set_u16,                   SPINEL_PROP_WS_COORD_SHORT_ADDRESS,              },
    { macShortAddress,                 wsmac_spinel_set_u16,                   SPINEL_PROP_MAC_15_4_SADDR,                      },
    { macAckWaitDuration,              wsmac_spinel_set_u16,                   SPINEL_PROP_WS_ACK_WAIT_DURATION,                },
    { mac802_15_4Mode,                 wsmac_spinel_set_u32,                   SPINEL_PROP_WS_15_4_MODE,                        },
    { macAsyncFragmentation,           wsmac_spinel_set_u32,                   SPINEL_PROP_WS_ASYNC_FRAGMENTATION,              },
    { macAutoRequestKeySource,         wsmac_spinel_set_eui64,                 SPINEL_PROP_WS_AUTO_REQUEST_KEY_SOURCE,          },
    { macCoordExtendedAddress,         wsmac_spinel_set_eui64,                 SPINEL_PROP_WS_COORD_EXTENDED_ADDRESS,           },
    { macDefaultKeySource,             wsmac_spinel_set_eui64,                 SPINEL_PROP_WS_DEFAULT_KEY_SOURCE,               },
    { macCCAThresholdStart,            wsmac_spinel_set_cca_threshold_start,   SPINEL_PROP_WS_CCA_THRESHOLD_START,              },
    { macRfConfiguration,              wsmac_spinel_set_rf_configuration,      SPINEL_PROP_WS_RF_CONFIGURATION_LEGACY,          },
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
    { 0 /* Special */,                 wsmac_spinel_ws_mcps_drop,              SPINEL_PROP_WS_MCPS_DROP,                        },
    { 0 /* Special */,                 wsmac_spinel_data_req,                  SPINEL_PROP_STREAM_RAW,                          },
    { macRxSensitivity,                NULL /* get only */,                    SPINEL_PROP_WS_RX_SENSITIVITY                    },
    { }
};

#define SPINEL_SIZE_MAX (MAC_IEEE_802_15_4G_MAX_PHY_PACKET_SIZE + 70)

// Warning, no re-entrancy for any of indications or confirmations.
static struct iobuf_write __tx_buf;
static struct iobuf_write *tx_buf = (struct iobuf_write *)&__tx_buf;

void spinel_push_hdr_is_prop(struct wsmac_ctxt *ctxt, struct iobuf_write *buf, unsigned int prop)
{
    spinel_push_u8(buf, wsbr_get_spinel_hdr(ctxt));
    spinel_push_uint(buf, SPINEL_CMD_PROP_IS);
    spinel_push_uint(buf, prop);
}

static void wsmac_rf_status_ind(struct wsmac_ctxt *ctxt, int status)
{
    iobuf_free(tx_buf);
    spinel_push_hdr_is_prop(ctxt, tx_buf, SPINEL_PROP_WS_RF_CONFIGURATION_LEGACY);
    spinel_push_uint(tx_buf, status ? SPINEL_STATUS_FAILURE : SPINEL_STATUS_OK);
    uart_tx(ctxt->os_ctxt, tx_buf->data, tx_buf->len);
}

static void wsmac_spinel_get_hw_addr(struct wsmac_ctxt *ctxt)
{
    iobuf_free(tx_buf);
    spinel_push_hdr_is_prop(ctxt, tx_buf, SPINEL_PROP_HWADDR);
    spinel_push_fixed_u8_array(tx_buf, ctxt->eui64, 8);
    uart_tx(ctxt->os_ctxt, tx_buf->data, tx_buf->len);
}

void wsmac_rx_host(struct wsmac_ctxt *ctxt)
{
    static uint8_t rx_buf_data[SPINEL_SIZE_MAX];
    struct iobuf_read rx_buf = { };
    int cmd, prop;
    int i;

    rx_buf.data_size = uart_rx(ctxt->os_ctxt, rx_buf_data, sizeof(rx_buf_data));
    rx_buf.data = rx_buf_data;
    if (!rx_buf.data_size)
        return;
    spinel_trace_rx(&rx_buf);
    spinel_pop_u8(&rx_buf); /* packet header */
    cmd = spinel_pop_uint(&rx_buf);
    if (cmd == SPINEL_CMD_PROP_GET || cmd == SPINEL_CMD_PROP_SET) {
        prop = spinel_pop_uint(&rx_buf);
        for (i = 0; mlme_prop_cstr[i].prop; i++)
            if (prop == mlme_prop_cstr[i].prop)
                break;
    }

    if (cmd == SPINEL_CMD_RESET) {
        ns_sw_mac_fhss_unregister(ctxt->rcp_mac_api);
        ns_fhss_delete(ctxt->fhss_api);
        memset(ctxt->neighbor_timings, 0, sizeof(ctxt->neighbor_timings));
        ctxt->fhss_api = NULL;
        ctxt->rcp_mac_api = init_mac_api(ctxt->rcp_driver_id);
        wsmac_reset_ind(ctxt, false);
    } else if (cmd == SPINEL_CMD_PROP_GET && prop == SPINEL_PROP_HWADDR) {
        int index = spinel_pop_uint(&rx_buf);

        WARN_ON(index != 0);
        BUG_ON(iobuf_remaining_size(&rx_buf));
        wsmac_spinel_get_hw_addr(ctxt);
    } else if (cmd == SPINEL_CMD_PROP_GET && prop == SPINEL_PROP_WS_RF_CONFIGURATION_LIST) {
        BUG_ON(iobuf_remaining_size(&rx_buf));
        wsmac_spinel_get_rf_configs(ctxt);
    } else if (cmd == SPINEL_CMD_PROP_GET) {
        int index = spinel_pop_uint(&rx_buf);
        mlme_get_t req = {
            .attr_index = index,
            .attr = mlme_prop_cstr[i].attr,
        };

        BUG_ON(iobuf_remaining_size(&rx_buf));
        ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_GET, &req);
    } else if (cmd == SPINEL_CMD_PROP_SET) {
        if (mlme_prop_cstr[i].prop_set)
            mlme_prop_cstr[i].prop_set(ctxt, mlme_prop_cstr[i].attr, &rx_buf);
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
        iobuf_free(tx_buf);
        spinel_push_hdr_is_prop(ctxt, tx_buf, SPINEL_PROP_WS_DEVICE_TABLE);
        spinel_push_uint(tx_buf, req->attr_index);
        spinel_push_u16(tx_buf,  descr->PANId);
        spinel_push_u16(tx_buf,  descr->ShortAddress);
        spinel_push_fixed_u8_array(tx_buf, descr->ExtAddress, 8);
        spinel_push_u32(tx_buf,  descr->FrameCounter);
        spinel_push_bool(tx_buf, descr->Exempt);
        uart_tx(ctxt->os_ctxt, tx_buf->data, tx_buf->len);
        break;
    }
    case macFrameCounter: {
        const uint32_t *descr = req->value_pointer;

        BUG_ON(req->value_size != sizeof(uint32_t));
        //BUG_ON(req->attr_index != XXXsecurity_frame_counter);
        iobuf_free(tx_buf);
        spinel_push_hdr_is_prop(ctxt, tx_buf, SPINEL_PROP_WS_FRAME_COUNTER);
        spinel_push_uint(tx_buf, req->attr_index);
        spinel_push_u32(tx_buf, *descr);
        uart_tx(ctxt->os_ctxt, tx_buf->data, tx_buf->len);
        break;
    }
    case macCCAThreshold: {
        BUG_ON(req->value_size > 200);
        iobuf_free(tx_buf);
        spinel_push_hdr_is_prop(ctxt, tx_buf, SPINEL_PROP_WS_CCA_THRESHOLD);
        spinel_push_data(tx_buf, req->value_pointer, req->value_size);
        uart_tx(ctxt->os_ctxt, tx_buf->data, tx_buf->len);
        break;
    }

    case macRxSensitivity: {
        iobuf_free(tx_buf);
        spinel_push_hdr_is_prop(ctxt, tx_buf, SPINEL_PROP_WS_RX_SENSITIVITY);
        spinel_push_i16(tx_buf, -93);
        uart_tx(ctxt->os_ctxt, tx_buf->data, tx_buf->len);
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
    iobuf_free(tx_buf);
    spinel_push_hdr_is_prop(ctxt, tx_buf, SPINEL_PROP_LAST_STATUS);
    spinel_push_uint(tx_buf, SPINEL_STATUS_OK);
    uart_tx(ctxt->os_ctxt, tx_buf->data, tx_buf->len);
}

void wsmac_mlme_confirm(const mac_api_t *mac_api, mlme_primitive_e id, const void *data)
{
    struct wsmac_ctxt *ctxt = &g_ctxt;
    static const struct {
        int id;
        void (*fn)(struct wsmac_ctxt *, const void *);
    } table[] = {
        { MLME_GET,   wsmac_mlme_get },
        { MLME_START, wsmac_mlme_start },
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

    iobuf_free(tx_buf);
    spinel_push_hdr_is_prop(ctxt, tx_buf, SPINEL_PROP_STREAM_STATUS);
    spinel_push_u8(tx_buf,   data->status);
    spinel_push_u8(tx_buf,   data->msduHandle);
    spinel_push_u32(tx_buf,  data->timestamp);
    spinel_push_u8(tx_buf,   data->cca_retries);
    spinel_push_u8(tx_buf,   data->tx_retries);
    spinel_push_data(tx_buf, conf_data->headerIeList, conf_data->headerIeListLength);
    spinel_push_data(tx_buf, conf_data->payloadIeList, conf_data->payloadIeListLength);
    spinel_push_data(tx_buf, conf_data->payloadPtr, conf_data->payloadLength);
    uart_tx(ctxt->os_ctxt, tx_buf->data, tx_buf->len);

    malloc_info = SLIST_REMOVE(ctxt->msdu_malloc_list, malloc_info,
                               list, malloc_info->msduHandle == data->msduHandle);
    BUG_ON(!malloc_info);
    free(malloc_info->header->iov_base);
    free(malloc_info->payload->iov_base);
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

    iobuf_free(tx_buf);
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
    uart_tx(ctxt->os_ctxt, tx_buf->data, tx_buf->len);
}

void wsmac_mcps_data_indication(const mac_api_t *mac_api, const mcps_data_ind_t *data)
{
    wsmac_mcps_data_indication_ext(mac_api, data, NULL);
}


void wsmac_mcps_purge_confirm(const mac_api_t *mac_api, mcps_purge_conf_t *data)
{
    WARN("not implemented");
}

void wsmac_mlme_indication(const mac_api_t *mac_api, mlme_primitive_e id, const void *data)
{
    struct wsmac_ctxt *ctxt = &g_ctxt;
    int data_len;

    BUG_ON(!mac_api);
    BUG_ON(mac_api != ctxt->rcp_mac_api);
    switch (id) {
        case MLME_BEACON_NOTIFY: {
            DEBUG("dataInd MLME_BEACON_NOTIFY indication not yet supported");
            data_len = 0;
            break;
        }
        case MLME_COMM_STATUS: {
            mlme_comm_status_t *status = (mlme_comm_status_t *)data;
            DEBUG("dataInd: Cannot decrypt frame: (key %d == %s)", status->Key.KeyIdMode, tr_key(status->Key.Keysource, 8));
            data_len = sizeof(mlme_comm_status_t);
            break;
        }
        case MLME_SYNC_LOSS: {
            DEBUG("dataInd MLME_SYNC_LOSS ignored");
            data_len = 0;
            break;
        }
        default: {
            DEBUG("dataInd MLME indication ignored");
            data_len = 0;
        }
    }

    iobuf_free(tx_buf);
    spinel_push_hdr_is_prop(ctxt, tx_buf, SPINEL_PROP_WS_MLME_IND);
    spinel_push_uint(tx_buf, id);
    spinel_push_data(tx_buf, data, data_len);
    uart_tx(ctxt->os_ctxt, tx_buf->data, tx_buf->len);
}

// Copy-paste from stack/source/6lowpan/mac/mac_ie_lib.c
#define MAC_IE_HEADER_LENGTH_MASK 0x007f
#define MAC_IE_HEADER_ID_MASK     0x7f80

// Copy-paste from stack/source/6lowpan/ws/ws_neighbor_class.c
static uint8_t ws_neighbor_class_rsl_from_dbm_calculate(int8_t dbm_heard)
{
    /* RSL MUST be calculated as the received signal level relative to standard
     * thermal noise (290oK) at 1 Hz bandwidth or 174 dBm.
     * This provides a range of -174 (0) to +80 (254) dBm.
     */

    return dbm_heard + 174;
}

// Copy-paste from stack/source/6lowpan/mac/mac_ie_lib.c
#define WH_IE_UTT_TYPE              1   /**< Unicast Timing and Frame type information */
#define WH_IE_RSL_TYPE              4   /**< Received Signal Level information */

#define WS_FT_ACK                   5   /**< Enhanced ACK */

static uint8_t *mac_ie_header_base_write(uint8_t *ptr, uint8_t type, uint16_t length)
{
    uint16_t ie_dummy = 0; //Header Type
    ie_dummy |= (length & MAC_IE_HEADER_LENGTH_MASK);
    ie_dummy |= ((type << 7) &  MAC_IE_HEADER_ID_MASK);
    return write_le16(ptr, ie_dummy);
}

// Copy-paste from stack/source/6lowpan/ws/ws_ie_lib.c
static uint8_t *ws_wh_header_base_write(uint8_t *ptr, uint16_t length, uint8_t type)
{
    ptr = mac_ie_header_base_write(ptr, MAC_HEADER_ASSIGNED_EXTERNAL_ORG_IE_ID, length + 1);
    *ptr++ = type;
    return ptr;
}

// Copy-paste from stack/source/6lowpan/ws/ws_ie_lib.c
static uint8_t *ws_wh_utt_write(uint8_t *ptr, uint8_t message_type)
{
    ptr = ws_wh_header_base_write(ptr, 4, WH_IE_UTT_TYPE);
    *ptr++ = message_type;
    memset(ptr, 0, 3);
    ptr += 3;
    return ptr;
}

// Copy-paste from stack/source/6lowpan/ws/ws_ie_lib.c
static uint8_t *ws_wh_rsl_write(uint8_t *ptr, uint8_t rsl)
{
    ptr = ws_wh_header_base_write(ptr, 1, WH_IE_RSL_TYPE);
    *ptr++ = rsl;
    return ptr;
}

// Inspired from ws_llc_ack_data_req_ext() from stack/source/6lowpan/ws/ws_llc_data_service.c
void wsmac_mcps_ack_data_req_ext(const mac_api_t *mac_api, mcps_ack_data_payload_t *data,
                                 int8_t rssi, uint8_t lqi)
{
    // It is safe to use static buffer. Indeed, result of this function is
    // always stored in enhanced_ack_buffer that is instanciated only once for
    // each MAC.
    static struct iovec header_vector;
    static uint8_t ie[20];

    memset(data, 0, sizeof(mcps_ack_data_payload_t));
    data->ie_elements.headerIovLength = 1;
    data->ie_elements.headerIeVectorList = &header_vector;
    data->ie_elements.headerIeVectorList->iov_base = ie;

    // Write Data to block
    uint8_t *ptr = ie;
    ptr = ws_wh_utt_write(ptr, WS_FT_ACK);
    ptr = ws_wh_rsl_write(ptr, ws_neighbor_class_rsl_from_dbm_calculate(rssi));
    data->ie_elements.headerIeVectorList->iov_len = ptr - ie;
}

void wsmac_mcps_edfe_handler(const mac_api_t *mac_api, mcps_edfe_response_t *response_message)
{
    WARN("not implemented");
}

static void wsmac_spinel_get_rf_configs(struct wsmac_ctxt *ctxt)
{
    static const struct {
        uint32_t channel_base;
        uint32_t channel_spacing;
        uint32_t channel_nb;
        uint8_t phy_mode_id;
    } simulated_rf_configs[] = {
        {  470200000, 200000, 199,  2 },
        {  470200000, 200000, 199,  3 },
        {  470200000, 200000, 199,  5 },
        {  779200000, 200000,  39,  2 },
        {  779200000, 200000,  39,  3 },
        {  779400000, 400000,  19,  5 },
        {  779400000, 400000,  19,  6 },
        {  779400000, 400000,  19,  8 },
        {  863100000, 100000,  69,  1 },
        {  863100000, 200000,  35,  3 },
        {  863100000, 200000,  35,  5 },
        {  863100000, 200000,  35, 80 },
        {  865100000, 100000,  19,  1 },
        {  865100000, 200000,  10,  3 },
        {  865100000, 200000,  10,  5 },
        {  866100000, 100000,  29,  1 },
        {  866100000, 200000,  15,  3 },
        {  866100000, 200000,  15,  5 },
        {  866300000, 400000,   7,  6 },
        {  866300000, 400000,   7,  8 },
        {  870100000, 100000,  55,  1 },
        {  870200000, 200000,  27,  3 },
        {  870200000, 200000,  27,  5 },
        {  870200000, 200000,  27, 80 },
        {  902200000, 200000,  90,  2 },
        {  902200000, 200000,  90,  3 },
        {  902200000, 200000,  90, 80 },
        {  902200000, 200000, 129,  2 },
        {  902200000, 200000, 129,  3 },
        {  902200000, 200000, 129, 80 },
        {  902400000, 400000,  43,  5 },
        {  902400000, 400000,  43,  6 },
        {  902400000, 400000,  43, 64 },
        {  902400000, 400000,  64,  5 },
        {  902400000, 400000,  64,  6 },
        {  902400000, 400000,  64, 64 },
        {  902400000, 400000,  43,  8 }, // FIXME: check that
        {  902400000, 400000,  64,  8 }, // FIXME: check that
        {  902600000, 600000,  42,  8 },
        {  902600000, 600000,  28,  8 },
        {  915200000, 200000,  14,  2 },
        {  915200000, 200000,  64,  2 },
        {  915200000, 200000,  14,  2 },
        {  915200000, 200000,  64,  3 },
        {  915200000, 200000,  14,  3 },
        {  915200000, 200000,  64,  3 },
        {  915400000, 400000,  32,  5 },
        {  915400000, 400000,   7,  5 },
        {  915400000, 400000,  32,  6 },
        {  915400000, 400000,   7,  6 },
        {  915400000, 400000,  32,  8 },
        {  915400000, 400000,   7,  8 },
        {  917100000, 200000,  32,  2 },
        {  917100000, 200000,  32,  3 },
        {  917300000, 400000,  16,  5 },
        {  917300000, 400000,  16,  6 },
        {  917300000, 400000,  16,  8 },
        {  919200000, 200000,  19,  2 },
        {  919200000, 200000,  19,  3 },
        {  919400000, 400000,  10,  5 },
        {  919400000, 400000,  10,  6 },
        {  919400000, 400000,  10,  8 },
        {  920200000, 200000,  24,  2 },
        {  920200000, 200000,  24,  3 },
        {  920400000, 400000,  12,  5 },
        {  920400000, 400000,  12,  6 },
        {  920400000, 400000,  12,  8 },
        {  920600000, 200000,  38,  2 },
        {  920625000, 250000,  16,  2 },
        {  920625000, 250000,  16,  3 },
        {  920625000, 250000,  16,  5 },
        {  920800000, 600000,  12,  7 },
        {  920800000, 600000,  12,  8 },
        {  920900000, 400000,  18,  4 },
        {  920900000, 400000,  18,  5 },
        { 2400200000, 200000, 416,  2 },
        { 2400200000, 200000, 416,  3 },
        { 2400400000, 400000, 207,  5 },
        { 2400400000, 400000, 207,  6 },
        { 2400400000, 400000, 207,  8 },
    };
    int i;

    iobuf_free(tx_buf);
    spinel_push_hdr_is_prop(ctxt, tx_buf, SPINEL_PROP_WS_RF_CONFIGURATION_LIST);

    for (i = 0; i < ARRAY_SIZE(simulated_rf_configs); i++) {
        spinel_push_u32(tx_buf, simulated_rf_configs[i].channel_base);
        spinel_push_u32(tx_buf, simulated_rf_configs[i].channel_spacing);
        spinel_push_u16(tx_buf, simulated_rf_configs[i].channel_nb);
        spinel_push_u8(tx_buf, simulated_rf_configs[i].phy_mode_id);
        spinel_push_u8(tx_buf, 0); // reserved for alignement
    }
    uart_tx(ctxt->os_ctxt, tx_buf->data, tx_buf->len);
}

void wsmac_reset_ind(struct wsmac_ctxt *ctxt, bool hw)
{
    // If garabage has already been sent, flush it
    iobuf_free(tx_buf);
    spinel_push_u8(tx_buf, wsbr_get_spinel_hdr(ctxt));
    spinel_push_uint(tx_buf, SPINEL_CMD_NOOP);
    uart_tx(ctxt->os_ctxt, tx_buf->data, tx_buf->len);

    iobuf_free(tx_buf);
    spinel_push_u8(tx_buf, wsbr_get_spinel_hdr(ctxt));
    spinel_push_uint(tx_buf, SPINEL_CMD_RESET);
    spinel_push_u32(tx_buf, version_hwsim_api);
    spinel_push_u32(tx_buf, version_hwsim);
    spinel_push_str(tx_buf, version_hwsim_str);
    spinel_push_bool(tx_buf, hw);
    spinel_push_u8(tx_buf, g_storage_sizes.device_description_table_size);
    spinel_push_u8(tx_buf, g_storage_sizes.key_description_table_size);
    spinel_push_u8(tx_buf, g_storage_sizes.key_lookup_size);
    spinel_push_u8(tx_buf, g_storage_sizes.key_usage_size);

    // Further bytes reserved for RF parameters
    spinel_push_u32(tx_buf, 0);
    spinel_push_u32(tx_buf, 0);
    spinel_push_u8(tx_buf, 0);
    spinel_push_u8(tx_buf, 0);
    spinel_push_u8(tx_buf, 0);
    uart_tx(ctxt->os_ctxt, tx_buf->data, tx_buf->len);
}
