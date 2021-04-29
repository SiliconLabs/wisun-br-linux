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

#include "hal_fhss_timer.h"
#include "bus_uart.h"
#include "wsmac_mac.h"
#include "wsmac.h"
#include "spinel.h"
#include "utils.h"
#include "log.h"

static uint8_t wsbr_get_spinel_hdr(struct wsmac_ctxt *ctxt)
{
    uint8_t hdr = FIELD_PREP(0xC0, 0x2) | FIELD_PREP(0x30, ctxt->spinel_iid);

    ctxt->spinel_tid = (ctxt->spinel_tid + 1) % 0x10;
    if (!ctxt->spinel_tid)
        ctxt->spinel_tid = 1;
    hdr |= FIELD_PREP(0x0F, ctxt->spinel_tid);
    return hdr;
}

static void wsmac_spinel_set_bool(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    bool data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };

    BUG_ON(frame_len != sizeof(data));
    spinel_datatype_unpack(frame, frame_len, "b", &data);
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_u8(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    uint8_t data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };

    BUG_ON(frame_len != sizeof(data));
    spinel_datatype_unpack(frame, frame_len, "C", &data);
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_u16(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    uint16_t data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };

    BUG_ON(frame_len != sizeof(data));
    spinel_datatype_unpack(frame, frame_len, "S", &data);
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_u32(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    uint32_t data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };

    BUG_ON(frame_len != sizeof(data));
    spinel_datatype_unpack(frame, frame_len, "L", &data);
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_eui64(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    mlme_set_t req = {
        .attr = attr,
        .value_size = 8,
    };

    BUG_ON(frame_len != 8);
    spinel_datatype_unpack(frame, frame_len, "E", &req.value_pointer);
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_data(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = frame,
        .value_size = frame_len,
    };

    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_cca_threshold(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    int data_len;
    mlme_set_t req = {
        .attr = attr,
    };

    BUG_ON(frame_len != sizeof(uint8_t));
    spinel_datatype_unpack(frame, frame_len, "d", &req.value_pointer, &data_len);
    req.value_size = data_len;
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_cca_threshold_start(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    uint8_t data[4];
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = data,
        .value_size = sizeof(data),
    };

    spinel_datatype_unpack(frame, frame_len, "CCCC", &data[0], &data[1], &data[2], &data[3]);
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_multi_csma_parameters(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    struct mlme_multi_csma_ca_s data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };

    spinel_datatype_unpack(frame, frame_len, "CS",
                           &data.number_of_csma_ca_periods,
                           &data.multi_cca_interval);
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_rf_configuration(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    struct phy_rf_channel_configuration_s data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };
    uint8_t tmp[2];

    spinel_datatype_unpack(frame, frame_len, "LLLSCC",
                           &data.channel_0_center_frequency,
                           &data.channel_spacing, &data.datarate,
                           &data.number_of_channels, &tmp[0],
                           &tmp[1]);
    data.modulation = tmp[0];
    data.modulation_index = tmp[1];
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_device_table(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    struct mlme_device_descriptor_s data;
    bool exempt;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };
    int ret;

    ret = spinel_datatype_unpack_in_place(frame, frame_len, "CSSELb",
                           &req.attr_index, &data.PANId, &data.ShortAddress,
                           data.ExtAddress, &data.FrameCounter,
                           &exempt);
    BUG_ON(ret != frame_len);
    data.Exempt = exempt;
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_key_table(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
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
    int len_key = sizeof(data.Key);
    int len_data = sizeof(data.KeyIdLookupList->LookupData);
    int ret;

    BUG_ON(attr != macKeyTable);
    ret = spinel_datatype_unpack_in_place(frame, frame_len, "Cdd", &req.attr_index,
                                   data.Key, &len_key,
                                   data.KeyIdLookupList->LookupData, &len_data);
    BUG_ON(ret != frame_len);
    BUG_ON(len_key != sizeof(data.Key));
    if (len_data) {
        data.KeyIdLookupListEntries = 1;
        if (len_data == 9)
            data.KeyIdLookupList->LookupDataSize = 1;
        else
            BUG_ON(len_data != 5);
    }
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_set_frame_counter(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    uint32_t data;
    mlme_set_t req = {
        .attr = attr,
        .value_pointer = &data,
        .value_size = sizeof(data),
    };
    int ret;

    ret = spinel_datatype_unpack(frame, frame_len, "iL",
                           &req.attr_index, req.value_pointer);
    BUG_ON(ret != frame_len);
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_SET, &req);
}

static void wsmac_spinel_fhss_set_parent(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    uint8_t *eui64;
    broadcast_timing_info_t bc_timing_info;
    bool force_synch;
    uint8_t tmp;
    int ret;

    ret = spinel_datatype_unpack(frame, frame_len, "EbCCSSSLLL",
                           &eui64, &force_synch,
                           &tmp,
                           &bc_timing_info.broadcast_dwell_interval,
                           &bc_timing_info.fixed_channel,
                           &bc_timing_info.broadcast_slot,
                           &bc_timing_info.broadcast_schedule_id,
                           &bc_timing_info.broadcast_interval_offset,
                           &bc_timing_info.broadcast_interval,
                           &bc_timing_info.bt_rx_timestamp);
    BUG_ON(ret != frame_len);
    bc_timing_info.broadcast_channel_function = tmp;
    ns_fhss_ws_set_parent(ctxt->fhss_api, eui64, &bc_timing_info, force_synch);
}

static void wsmac_spinel_set_frame_counter_per_key(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    bool data;

    BUG_ON(frame_len != sizeof(bool));
    spinel_datatype_unpack(frame, frame_len, "b", &data);
    ns_sw_mac_enable_frame_counter_per_key(ctxt->rcp_mac_api, data);
}

static void wsmac_spinel_fhss_set_neighbor(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    const uint8_t *eui64;
    struct fhss_ws_neighbor_timing_info *fhss_data = NULL;
    uint8_t tmp;
    int tmp_len, i;

    spinel_datatype_unpack(frame, frame_len, "E", &eui64);
    for (i = 0; i < ARRAY_SIZE(ctxt->neighbor_timings); i++)
        if (!memcmp(ctxt->neighbor_timings[i].eui64, eui64, 8))
            fhss_data = &ctxt->neighbor_timings[i].val;
    if (!fhss_data) {
        // FIXME: What about removing entries?
        TRACE("add new entry");
        for (i = 0; i < ARRAY_SIZE(ctxt->neighbor_timings); i++) {
            if (!memcmp(ctxt->neighbor_timings[i].eui64,
                        "\x00\x00\x00\x00\x00\x00\x00\x00", 8)) {
                fhss_data = &ctxt->neighbor_timings[i].val;
                memcpy(ctxt->neighbor_timings[i].eui64, eui64, 8);
            }
        }
    }
    if (WARN_ON(!fhss_data))
        return;

    spinel_datatype_unpack_in_place(frame, frame_len, "ECCSdCCSSLL",
                           NULL, &fhss_data->clock_drift, &fhss_data->timing_accuracy,
                           &fhss_data->uc_channel_list.channel_count,
                           fhss_data->uc_channel_list.channel_mask, &tmp_len,
                           &tmp,
                           &fhss_data->uc_timing_info.unicast_dwell_interval,
                           &fhss_data->uc_timing_info.unicast_number_of_channels,
                           &fhss_data->uc_timing_info.fixed_channel,
                           &fhss_data->uc_timing_info.ufsi,
                           &fhss_data->uc_timing_info.utt_rx_timestamp);
    fhss_data->uc_timing_info.unicast_channel_function = tmp;
    BUG_ON(tmp_len != sizeof(fhss_data->uc_channel_list.channel_mask));
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

static void wsmac_spinel_fhss_create(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    struct fhss_ws_configuration config = { };
    uint8_t tmp[2];
    int tmp1_len = sizeof(config.channel_mask);
    int tmp2_len = sizeof(config.channel_mask);
    int ret;

    ret = spinel_datatype_unpack_in_place(frame, frame_len, "CCSCLCCCddC",
                           &tmp[0],
                           &tmp[1],
                           &config.bsi,
                           &config.fhss_uc_dwell_interval,
                           &config.fhss_broadcast_interval,
                           &config.fhss_bc_dwell_interval,
                           &config.unicast_fixed_channel,
                           &config.broadcast_fixed_channel,
                           config.channel_mask, &tmp1_len,
                           config.unicast_channel_mask, &tmp2_len,
                           &config.config_parameters.number_of_channel_retries);
    BUG_ON(ret != frame_len);
    config.ws_uc_channel_function = tmp[0];
    config.ws_bc_channel_function = tmp[1];
    BUG_ON(tmp1_len != sizeof(config.channel_mask));
    BUG_ON(tmp2_len != sizeof(config.unicast_channel_mask));
    ctxt->fhss_api = ns_fhss_ws_create(&config, &wsbr_fhss);
    BUG_ON(!ctxt->fhss_api);
    ns_fhss_set_neighbor_info_fp(ctxt->fhss_api, wsmac_fhss_get_neighbor_info);
}

static void wsmac_spinel_fhss_delete(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    ns_fhss_delete(ctxt->fhss_api);
    ctxt->fhss_api = NULL;
}

static void wsmac_spinel_fhss_set_conf(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    struct fhss_ws_configuration config = { };
    uint8_t tmp[2];
    int tmp1_len = sizeof(config.channel_mask);
    int tmp2_len = sizeof(config.channel_mask);
    int ret;

    ret = spinel_datatype_unpack_in_place(frame, frame_len, "CCSCLCCCddC",
                                    &tmp[0],
                                    &tmp[1],
                                    &config.bsi,
                                    &config.fhss_uc_dwell_interval,
                                    &config.fhss_broadcast_interval,
                                    &config.fhss_bc_dwell_interval,
                                    &config.unicast_fixed_channel,
                                    &config.broadcast_fixed_channel,
                                    config.channel_mask, &tmp1_len,
                                    config.unicast_channel_mask, &tmp2_len,
                                    &config.config_parameters.number_of_channel_retries);
    BUG_ON(ret != frame_len);
    config.ws_uc_channel_function = tmp[0];
    config.ws_bc_channel_function = tmp[1];
    BUG_ON(tmp1_len != sizeof(config.channel_mask));
    BUG_ON(tmp2_len != sizeof(config.unicast_channel_mask));
    ns_fhss_ws_configuration_set(ctxt->fhss_api, &config);
}

static void wsmac_spinel_fhss_set_hop_count(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    uint8_t data;
    int ret;

    BUG_ON(frame_len != sizeof(uint8_t));
    ret = spinel_datatype_unpack(frame, frame_len, "C", &data);
    BUG_ON(ret != frame_len);
    ns_fhss_ws_set_hop_count(ctxt->fhss_api, data);
}

static void wsmac_spinel_fhss_register(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    struct fhss_api *fhss_api = ns_sw_mac_get_fhss_api(ctxt->rcp_mac_api);

    TRACE();
    BUG_ON(fhss_api, "fhss_api already regstered");
    BUG_ON(!ctxt->fhss_api, "fhss_api not yet created");
    ns_sw_mac_fhss_register(ctxt->rcp_mac_api, ctxt->fhss_api);
}

static void wsmac_spinel_fhss_unregister(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    struct fhss_api *fhss_api = ns_sw_mac_get_fhss_api(ctxt->rcp_mac_api);

    TRACE();
    BUG_ON(fhss_api != ctxt->fhss_api);
    ns_sw_mac_fhss_unregister(ctxt->rcp_mac_api);
    ctxt->fhss_api = NULL;
}

static void wsmac_spinel_start(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    mlme_start_t req = { };
    uint8_t tmp8[2];
    bool tmpB;
    int ret;

    ret = spinel_datatype_unpack(frame, frame_len, "SCCLCCb",
                           &req.PANId, &req.LogicalChannel, &req.ChannelPage,
                           &req.StartTime, &tmp8[0], &tmp8[1], &tmpB);
    BUG_ON(ret != frame_len);
    req.BeaconOrder = tmp8[0];
    req.SuperframeOrder = tmp8[1];
    req.PANCoordinator = tmpB;
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_START, &req);
}

static void wsmac_spinel_reset(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    mlme_reset_t req = { };

    spinel_datatype_unpack(frame, frame_len, "b", &req.SetDefaultPIB);
    ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_RESET, &req);
}

static void wsmac_spinel_data_req(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len)
{
    struct mcps_data_req_s data;
    struct mcps_data_req_ie_list ie_ext = { };
    struct channel_list_s async_channel_list;
    uint8_t tmp8[4];
    bool tmpB[6];
    int tmpI;
    int len[4];
    void *buf[4];
    void *buf_fixed[2];
    int ret;

    ret = spinel_datatype_unpack(frame, frame_len, "dCCSECbbbbbbCCCEiddd",
                           &buf[0], &len[0],
                           &tmp8[0], &tmp8[1],
                           &data.DstPANId, &buf_fixed[0], &data.msduHandle,
                           &tmpB[0], &tmpB[1], &tmpB[2],
                           &tmpB[3], &tmpB[4], &tmpB[5],
                           &tmp8[2], &tmp8[3], &data.Key.KeyIndex,
                           &buf_fixed[1],
                           &tmpI,
                           &buf[1], &len[1],
                           &buf[2], &len[2],
                           &buf[3], &len[3]);
    BUG_ON(ret != frame_len);
    data.SrcAddrMode = tmp8[0];
    data.DstAddrMode = tmp8[1];
    data.TxAckReq = tmpB[0];
    data.InDirectTx = tmpB[1];
    data.PendingBit = tmpB[2];
    data.SeqNumSuppressed = tmpB[3];
    data.PanIdSuppressed = tmpB[4];
    data.ExtendedFrameExchange = tmpB[5];
    data.Key.SecurityLevel = tmp8[2];
    data.Key.KeyIdMode = tmp8[3];

    memcpy(data.DstAddr, buf_fixed[0], 8);
    memcpy(data.Key.Keysource, buf_fixed[1], 8);

    data.msduLength = len[0];
    data.msdu = malloc(len[0]);
    memcpy(data.msdu, buf[0], len[0]);

    async_channel_list.channel_page = tmpI;
    BUG_ON(sizeof(async_channel_list.channel_mask) != len[1]);
    memcpy(async_channel_list.channel_mask, buf[1], len[1]);

    if (len[2]) {
        ie_ext.payloadIovLength = 1;
        ie_ext.payloadIeVectorList = malloc(sizeof(struct ns_ie_iovec));
        ie_ext.payloadIeVectorList->iovLen = len[2];
        ie_ext.payloadIeVectorList->ieBase = malloc(len[2]);
        memcpy(ie_ext.payloadIeVectorList->ieBase, buf[2], len[2]);
    }
    if (len[2]) {
        ie_ext.headerIovLength = 1;
        ie_ext.headerIeVectorList = malloc(sizeof(struct ns_ie_iovec));
        ie_ext.headerIeVectorList->iovLen = len[2];
        ie_ext.headerIeVectorList->ieBase = malloc(len[2]);
        memcpy(ie_ext.headerIeVectorList->ieBase, buf[2], len[2]);
    }

    if (async_channel_list.channel_page != CHANNEL_PAGE_UNDEFINED)
        ctxt->rcp_mac_api->mcps_data_req_ext(ctxt->rcp_mac_api, &data, &ie_ext, &async_channel_list);
    else
        ctxt->rcp_mac_api->mcps_data_req_ext(ctxt->rcp_mac_api, &data, &ie_ext, NULL);
}

static const struct {
    const char *str;
    mlme_attr_t attr;
    void (*prop_set)(struct wsmac_ctxt *ctxt, mlme_attr_t attr, const void *frame, int frame_len);
    unsigned int prop;
} mlme_prop_cstr[] = {
    { "macRxOnWhenIdle",                 macRxOnWhenIdle,                 wsmac_spinel_set_bool,                  SPINEL_PROP_WS_RX_ON_WHEN_IDLE,                  },
    { "macSecurityEnabled",              macSecurityEnabled,              wsmac_spinel_set_bool,                  SPINEL_PROP_WS_SECURITY_ENABLED,                 },
    { "macAcceptByPassUnknowDevice",     macAcceptByPassUnknowDevice,     wsmac_spinel_set_bool,                  SPINEL_PROP_WS_ACCEPT_BYPASS_UNKNOW_DEVICE,      },
    { "macEdfeForceStop",                macEdfeForceStop,                wsmac_spinel_set_bool,                  SPINEL_PROP_WS_EDFE_FORCE_STOP,                  },
    { "macAssociationPermit",            macAssociationPermit,            wsmac_spinel_set_bool,                  SPINEL_PROP_WS_ASSOCIATION_PERMIT,               },
    { "phyCurrentChannel",               phyCurrentChannel,               wsmac_spinel_set_u8,                    SPINEL_PROP_PHY_CHAN,                            },
    { "macAutoRequestKeyIdMode",         macAutoRequestKeyIdMode,         wsmac_spinel_set_u8,                    SPINEL_PROP_WS_AUTO_REQUEST_KEY_ID_MODE,         },
    { "macAutoRequestKeyIndex",          macAutoRequestKeyIndex,          wsmac_spinel_set_u8,                    SPINEL_PROP_WS_AUTO_REQUEST_KEY_INDEX,           },
    { "macAutoRequestSecurityLevel",     macAutoRequestSecurityLevel,     wsmac_spinel_set_u8,                    SPINEL_PROP_WS_AUTO_REQUEST_SECURITY_LEVEL,      },
    { "macBeaconPayloadLength",          macBeaconPayloadLength,          wsmac_spinel_set_u8,                    SPINEL_PROP_WS_BEACON_PAYLOAD_LENGTH,            },
    { "macMaxFrameRetries",              macMaxFrameRetries,              wsmac_spinel_set_u8,                    SPINEL_PROP_WS_MAX_FRAME_RETRIES,                },
    { "macTXPower",                      macTXPower,                      wsmac_spinel_set_u8,                    SPINEL_PROP_PHY_TX_POWER,                        },
    { "macPANId",                        macPANId,                        wsmac_spinel_set_u16,                   SPINEL_PROP_MAC_15_4_PANID,                      },
    { "macCoordShortAddress",            macCoordShortAddress,            wsmac_spinel_set_u16,                   SPINEL_PROP_WS_COORD_SHORT_ADDRESS,              },
    { "macShortAddress",                 macShortAddress,                 wsmac_spinel_set_u16,                   SPINEL_PROP_MAC_15_4_SADDR,                      },
    { "macDeviceDescriptionPanIDUpdate", macDeviceDescriptionPanIDUpdate, wsmac_spinel_set_u16,                   SPINEL_PROP_WS_DEVICE_DESCRIPTION_PAN_ID_UPDATE, },
    { "macAckWaitDuration",              macAckWaitDuration,              wsmac_spinel_set_u16,                   SPINEL_PROP_WS_ACK_WAIT_DURATION,                },
    { "mac802_15_4Mode",                 mac802_15_4Mode,                 wsmac_spinel_set_u32,                   SPINEL_PROP_WS_15_4_MODE,                        },
    { "macAutoRequestKeySource",         macAutoRequestKeySource,         wsmac_spinel_set_eui64,                 SPINEL_PROP_WS_AUTO_REQUEST_KEY_SOURCE,          },
    { "macCoordExtendedAddress",         macCoordExtendedAddress,         wsmac_spinel_set_eui64,                 SPINEL_PROP_WS_COORD_EXTENDED_ADDRESS,           },
    { "macDefaultKeySource",             macDefaultKeySource,             wsmac_spinel_set_eui64,                 SPINEL_PROP_WS_DEFAULT_KEY_SOURCE,               },
    { "macBeaconPayload",                macBeaconPayload,                wsmac_spinel_set_data,                  SPINEL_PROP_WS_BEACON_PAYLOAD,                   },
    { "macCCAThreshold",                 macCCAThreshold,                 wsmac_spinel_set_cca_threshold,         SPINEL_PROP_WS_CCA_THRESHOLD,                    },
    { "macCCAThresholdStart",            macCCAThresholdStart,            wsmac_spinel_set_cca_threshold_start,   SPINEL_PROP_WS_CCA_THRESHOLD_START,              },
    { "macMultiCSMAParameters",          macMultiCSMAParameters,          wsmac_spinel_set_multi_csma_parameters, SPINEL_PROP_WS_MULTI_CSMA_PARAMETERS,            },
    { "macRfConfiguration",              macRfConfiguration,              wsmac_spinel_set_rf_configuration,      SPINEL_PROP_WS_RF_CONFIGURATION,                 },
    { "macDeviceTable",                  macDeviceTable,                  wsmac_spinel_set_device_table,          SPINEL_PROP_WS_DEVICE_TABLE,                     },
    { "macKeyTable",                     macKeyTable,                     wsmac_spinel_set_key_table,             SPINEL_PROP_WS_KEY_TABLE,                        },
    { "macFrameCounter",                 macFrameCounter,                 wsmac_spinel_set_frame_counter,         SPINEL_PROP_WS_FRAME_COUNTER,                    },
    { "fhssEnableFrameCounterPerKey",    0 /* Special */,                 wsmac_spinel_set_frame_counter_per_key, SPINEL_PROP_WS_ENABLE_FRAME_COUNTER_PER_KEY,     },
    { "fhssCreate",                      0 /* Special */,                 wsmac_spinel_fhss_create,               SPINEL_PROP_WS_FHSS_CREATE,                      },
    { "fhssDelete",                      0 /* Special */,                 wsmac_spinel_fhss_delete,               SPINEL_PROP_WS_FHSS_DELETE,                      },
    { "fhssRegister",                    0 /* Special */,                 wsmac_spinel_fhss_register,             SPINEL_PROP_WS_FHSS_REGISTER,                    },
    { "fhssUnregister",                  0 /* Special */,                 wsmac_spinel_fhss_unregister,           SPINEL_PROP_WS_FHSS_UNREGISTER,                  },
    { "fhssSetHopCount",                 0 /* Special */,                 wsmac_spinel_fhss_set_hop_count,        SPINEL_PROP_WS_FHSS_SET_HOP_COUNT,               },
    { "fhssSetConf",                     0 /* Special */,                 wsmac_spinel_fhss_set_conf,             SPINEL_PROP_WS_FHSS_SET_CONF,                    },
    { "fhssSetParent",                   0 /* Special */,                 wsmac_spinel_fhss_set_parent,           SPINEL_PROP_WS_FHSS_SET_PARENT,                  },
    { "fhssSetNeighbor",                 0 /* Special */,                 wsmac_spinel_fhss_set_neighbor,         SPINEL_PROP_WS_FHSS_SET_NEIGHBOR,                },
    { "mlmeStart",                       0 /* Special */,                 wsmac_spinel_start,                     SPINEL_PROP_WS_START,                            },
    { "mlmeReset",                       0 /* Special */,                 wsmac_spinel_reset,                     SPINEL_PROP_WS_RESET,                            },
    { "dataReq",                         0 /* Special */,                 wsmac_spinel_data_req,                  SPINEL_PROP_STREAM_RAW,                          },
    { }
};

void uart_rx(struct wsmac_ctxt *ctxt)
{
    uint8_t hdr;
    int cmd, prop;
    uint8_t buf[256];
    uint8_t *data;
    int len, data_len;
    int i;

    len = wsbr_uart_rx(ctxt->os_ctxt, buf, sizeof(buf));
    spinel_datatype_unpack(buf, len, "CiiD", &hdr, &cmd, &prop, &data, &data_len);
    for (i = 0; mlme_prop_cstr[i].prop; i++)
        if (prop == mlme_prop_cstr[i].prop)
            break;

    if (cmd == SPINEL_CMD_PROP_VALUE_GET) {
        int index;
        spinel_datatype_unpack(data, data_len, "i", &index);
        mlme_get_t req = {
            .attr_index = index,
            .attr = mlme_prop_cstr[i].attr,
        };
        TRACE("get %s", mlme_prop_cstr[i].str);
        ctxt->rcp_mac_api->mlme_req(ctxt->rcp_mac_api, MLME_GET, &req);
    } else if (cmd == SPINEL_CMD_PROP_VALUE_SET) {
        TRACE("set %s", mlme_prop_cstr[i].str);
        if (mlme_prop_cstr[i].prop_set)
            mlme_prop_cstr[i].prop_set(ctxt, mlme_prop_cstr[i].attr, data, data_len);
    } else {
        WARN("not implemented");
        return;
    }
}

void wsmac_mlme_get(struct wsmac_ctxt *ctxt, const void *data)
{
    const mlme_get_conf_t *req = data;

    TRACE("mlmeGet");
    switch (req->attr) {
    case macDeviceTable: {
        uint8_t hdr = wsbr_get_spinel_hdr(ctxt);
        const mlme_device_descriptor_t *req2 = req->value_pointer;
        uint8_t frame[1 + 3 + 3 + 3 + sizeof(uint8_t)];
        int frame_len;

        frame_len = spinel_datatype_pack(frame, sizeof(frame), "CiiiSSELb",
                                         hdr, SPINEL_CMD_PROP_VALUE_IS,
                                         SPINEL_PROP_WS_DEVICE_TABLE,
                                         req->attr_index, req2->PANId,
                                         req2->ShortAddress, req2->ExtAddress,
                                         req2->FrameCounter, req2->Exempt);
        wsbr_uart_tx(ctxt->os_ctxt, frame, frame_len);
        break;
    }
    case macFrameCounter: {
        uint8_t hdr = wsbr_get_spinel_hdr(ctxt);
        uint8_t frame[1 + 3 + 3 + 3 + sizeof(uint8_t)];
        int frame_len;

        BUG_ON(req->value_size != sizeof(uint32_t));
        //BUG_ON(req->attr_index != XXXsecurity_frame_counter);
        frame_len = spinel_datatype_pack(frame, sizeof(frame), "CiiiL", hdr,
                                         SPINEL_CMD_PROP_VALUE_IS,
                                         SPINEL_PROP_WS_FRAME_COUNTER,
                                         req->attr_index,
                                         *((uint32_t *)req->value_pointer));
        wsbr_uart_tx(ctxt->os_ctxt, frame, frame_len);
        break;
    }
    case macCCAThreshold: {
        uint8_t hdr = wsbr_get_spinel_hdr(ctxt);
        uint8_t frame[1 + 3 + 3 + 50 * sizeof(uint8_t)];
        int frame_len;

        BUG_ON(req->value_size > 50);
        frame_len = spinel_datatype_pack(frame, sizeof(frame), "Ciid", hdr,
                                         SPINEL_CMD_PROP_VALUE_IS,
                                         SPINEL_PROP_WS_CCA_THRESHOLD,
                                         req->value_pointer, req->value_size);
        wsbr_uart_tx(ctxt->os_ctxt, frame, frame_len);
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
    uint8_t hdr = wsbr_get_spinel_hdr(ctxt);
    uint8_t frame[1 + 3 + 3 + 3];
    int frame_len;

    TRACE("mlmeStart");
    WARN_ON(req->status);
    frame_len = spinel_datatype_pack(frame, sizeof(frame), "Ciii", hdr,
                                     SPINEL_CMD_PROP_VALUE_IS,
                                     SPINEL_PROP_LAST_STATUS,
                                     SPINEL_STATUS_OK);
    wsbr_uart_tx(ctxt->os_ctxt, frame, frame_len);
}

void wsmac_mlme_scan(struct wsmac_ctxt *ctxt, const void *data)
{
    //const mlme_scan_conf_t *req = data;

    WARN("not implemented");
}

void wsmac_mlme_confirm(const mac_api_t *api, mlme_primitive id, const void *data)
{
    struct wsmac_ctxt *ctxt = &g_ctxt;
    static const struct {
        uint32_t id;
        void (*fn)(struct wsmac_ctxt *, const void *);
    } table[] = {
        { MLME_GET,   wsmac_mlme_get },
        { MLME_START, wsmac_mlme_start },
        { MLME_SCAN,  wsmac_mlme_scan },
        { -1 },
    };
    int i;

    BUG_ON(!api);
    BUG_ON(ctxt->rcp_mac_api != api);
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
    struct wsmac_ctxt *ctxt = &g_ctxt;
    uint8_t hdr = wsbr_get_spinel_hdr(ctxt);
    uint8_t frame[2048];
    int frame_len;

    BUG_ON(!mac_api);
    BUG_ON(mac_api != ctxt->rcp_mac_api);
    BUG_ON(!conf_data, "not implemented");
    TRACE("dataCnf");
    frame_len = spinel_datatype_pack(frame, sizeof(frame), "CiiCCLCCddd",
                                     hdr, SPINEL_CMD_PROP_VALUE_IS, SPINEL_PROP_STREAM_STATUS,
                                     data->status, data->msduHandle,
                                     data->timestamp, data->cca_retries, data->tx_retries,
                                     conf_data->headerIeList, conf_data->headerIeListLength,
                                     conf_data->payloadIeList, conf_data->headerIeListLength,
                                     conf_data->payloadPtr, conf_data->payloadLength);
    BUG_ON(frame_len < 0);
    wsbr_uart_tx(ctxt->os_ctxt, frame, frame_len);
    WARN("FIXME: free msduHandle: %x", data->msduHandle);
}

void wsmac_mcps_data_confirm(const mac_api_t *mac_api, const mcps_data_conf_t *data)
{
    wsmac_mcps_data_confirm_ext(mac_api, data, NULL);
}

void wsmac_mcps_data_indication_ext(const mac_api_t *mac_api, const mcps_data_ind_t *data,
                                    const mcps_data_ie_list_t *ie_ext)
{
    struct wsmac_ctxt *ctxt = &g_ctxt;
    uint8_t hdr = wsbr_get_spinel_hdr(ctxt);
    uint8_t frame[2048];
    int frame_len;

    BUG_ON(!mac_api);
    BUG_ON(mac_api != ctxt->rcp_mac_api);
    BUG_ON(!ie_ext, "not implemented");
    TRACE("dataInd");
    frame_len = spinel_datatype_pack(frame, sizeof(frame), "CiidCSECSECcLbCCCCEdd",
                                     hdr, SPINEL_CMD_PROP_VALUE_IS, SPINEL_PROP_STREAM_RAW,
                                     data->msdu_ptr, data->msduLength,
                                     data->SrcAddrMode, data->SrcPANId, data->SrcAddr,
                                     data->DstAddrMode, data->DstPANId, data->DstAddr,
                                     data->mpduLinkQuality, data->signal_dbm, data->timestamp,
                                     data->DSN_suppressed, data->DSN,
                                     data->Key.SecurityLevel, data->Key.KeyIdMode,
                                     data->Key.KeyIndex, data->Key.Keysource,
                                     ie_ext->headerIeList, ie_ext->headerIeListLength,
                                     ie_ext->payloadIeList, ie_ext->headerIeListLength);
    BUG_ON(frame_len < 0);
    wsbr_uart_tx(ctxt->os_ctxt, frame, frame_len);
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
    uint8_t hdr = wsbr_get_spinel_hdr(ctxt);
    uint8_t frame[2048];
    int frame_len;
    int data_len = 0;

    BUG_ON(!mac_api);
    BUG_ON(mac_api != ctxt->rcp_mac_api);
    switch (id) {
        case MLME_BEACON_NOTIFY: {
            // data_len = sizeof(mlme_beacon_ind_t);
            TRACE("dataInd MLME_BEACON_NOTIFY indication not yet supported");
            break;
        }
        case MLME_COMM_STATUS: {
            TRACE("dataInd MLME_COMM_STATUS");
            data_len = sizeof(mlme_comm_status_t);
            break;
        }
        case MLME_SYNC_LOSS: {
            TRACE("dataInd MLME_SYNC_LOSS");
             data_len = sizeof(mlme_sync_loss_t);
            break;
        }
        default: {
            TRACE("dataInd MLME indication ignored");
        }
    }

    frame_len = spinel_datatype_pack(frame, sizeof(frame), "Ciiid",
                                     hdr, SPINEL_CMD_PROP_VALUE_IS, SPINEL_PROP_WS_MLME_IND,
                                     id, data, data_len);
    BUG_ON(frame_len < 0);
    wsbr_uart_tx(ctxt->os_ctxt, frame, frame_len);
}

void wsmac_mcps_ack_data_req_ext(const mac_api_t *mac_api, mcps_ack_data_payload_t *data,
                                 int8_t rssi, uint8_t lqi)
{
    WARN("not implemented");
}

void wsmac_mcps_edfe_handler(const mac_api_t *mac_api, mcps_edfe_response_t *response_message)
{
    WARN("not implemented");
}
