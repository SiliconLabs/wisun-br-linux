/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
/* MAC API imlementation */
#include <time.h>
#include <stdio.h>
#include <string.h>

#include "nanostack/mac_api.h"

#include "wsbr.h"
#include "wsbr_mac.h"
#include "utils.h"
#include "spinel.h"
#include "log.h"

void wsbr_rcp_reset(struct wsbr_ctxt *ctxt)
{
    uint8_t hdr = wsbr_get_spinel_hdr(ctxt);
    uint8_t frame[1 + 3];
    int frame_len;

    frame_len = spinel_datatype_pack(frame, sizeof(frame), "Ci", hdr, SPINEL_CMD_RESET);
    BUG_ON(frame_len <= 0);
    ctxt->rcp_tx(ctxt->os_ctxt, frame, frame_len);
}

void wsbr_rcp_get_hw_addr(struct wsbr_ctxt *ctxt)
{
    uint8_t hdr = wsbr_get_spinel_hdr(ctxt);
    uint8_t frame[1 + 3 + 3];
    int frame_len;

    frame_len = spinel_datatype_pack(frame, sizeof(frame), "Cii", hdr, SPINEL_CMD_PROP_VALUE_GET, SPINEL_PROP_HWADDR);
    BUG_ON(frame_len <= 0);
    ctxt->rcp_tx(ctxt->os_ctxt, frame, frame_len);
}

static void wsbr_spinel_is(struct wsbr_ctxt *ctxt, int prop, const void *frame, int frame_len)
{
    switch (prop) {
    case SPINEL_PROP_WS_DEVICE_TABLE: {
        struct mlme_device_descriptor_s data;
        uint8_t *ext_address;
        bool exempt;
        mlme_get_conf_t req = {
            .attr = macDeviceTable,
            .value_pointer = &data,
            .value_size = sizeof(data),
        };

        spinel_datatype_unpack(frame, sizeof(frame), "iSSELb",
                               &req.attr_index, &data.PANId, &data.ShortAddress,
                               &ext_address, &data.FrameCounter,
                               &exempt);
        memcpy(data.ExtAddress, ext_address, sizeof(uint8_t) * 8);
        data.Exempt = exempt;
        TRACE("cnf macDeviceTable");
        ctxt->mac_api.mlme_conf_cb(&ctxt->mac_api, MLME_GET, &req);
        break;
    }
    case SPINEL_PROP_WS_FRAME_COUNTER: {
        uint32_t data;
        mlme_get_conf_t req = {
            .attr = macFrameCounter,
            .value_pointer = &data,
            .value_size = sizeof(data),
        };

        spinel_datatype_unpack(frame, sizeof(frame), "iL",
                               &req.attr_index, &data);
        TRACE("cnf macFrameCounter");
        ctxt->mac_api.mlme_conf_cb(&ctxt->mac_api, MLME_GET, &req);
        break;
    }
    case SPINEL_PROP_WS_CCA_THRESHOLD: {
        mlme_get_conf_t req = {
            .attr = macCCAThreshold,
        };

        spinel_datatype_unpack(frame, sizeof(frame), "d",
                               &req.value_pointer, &req.value_size);
        TRACE("cnf macCCAThreshold");
        ctxt->mac_api.mlme_conf_cb(&ctxt->mac_api, MLME_GET, &req);
        break;
    }
    case SPINEL_PROP_WS_MLME_IND: {
        int id;
        void *data;

        BUG_ON(!ctxt->mac_api.mlme_ind_cb);
        spinel_datatype_unpack(frame, frame_len, "id",
                               &id, &data, NULL);
        TRACE("mlmeInd");
        ctxt->mac_api.mlme_ind_cb(&ctxt->mac_api, id, data);
        break;
    }
    case SPINEL_PROP_STREAM_STATUS: {
        mcps_data_conf_t req = { };
        mcps_data_conf_payload_t conf_req = { };
        int ret;
        int len[3];

        BUG_ON(!ctxt->mac_api.data_conf_ext_cb, "not implmemented");
        ret = spinel_datatype_unpack(frame, frame_len, "CCLCCddd",
                               &req.status, &req.msduHandle,
                               &req.timestamp, &req.cca_retries, &req.tx_retries,
                               &conf_req.headerIeList, &len[0],
                               &conf_req.payloadIeList, &len[1],
                               &conf_req.payloadPtr, &len[2]);
        BUG_ON(ret != frame_len);
        conf_req.headerIeListLength = len[0];
        conf_req.payloadIeListLength = len[1];
        conf_req.payloadLength = len[2];
        TRACE("dataCnf");
        if (ctxt->mac_api.data_conf_ext_cb)
            ctxt->mac_api.data_conf_ext_cb(&ctxt->mac_api, &req, &conf_req);
        else
            ctxt->mac_api.data_conf_cb(&ctxt->mac_api, &req);
        break;
    }
    case SPINEL_PROP_STREAM_RAW: {
        mcps_data_ind_t req = { };
        mcps_data_ie_list_t ie_ext = { };
        uint8_t tmp_u8[4];
        bool tmp_bool[1];
        void *tmp_ptr[3];
        int len[3];
        int ret;

        ret = spinel_datatype_unpack(frame, frame_len, "dCSECSECcLbCCCCEdd",
                               &req.msdu_ptr, &len[0],
                               &tmp_u8[0], &req.SrcPANId, &tmp_ptr[0],
                               &tmp_u8[1], &req.DstPANId, &tmp_ptr[1],
                               &req.mpduLinkQuality, &req.signal_dbm,
                               &req.timestamp, &tmp_bool[0], &req.DSN,
                               &tmp_u8[2], &tmp_u8[3],
                               &req.Key.KeyIndex, &tmp_ptr[2],
                               &ie_ext.headerIeList, &len[1],
                               &ie_ext.payloadIeList, &len[2]);
        BUG_ON(ret != frame_len);
        req.msduLength = len[0];
        ie_ext.headerIeListLength = len[1];
        ie_ext.payloadIeListLength = len[2];
        req.SrcAddrMode = tmp_u8[0];
        req.DstAddrMode = tmp_u8[1];
        memcpy(req.SrcAddr, tmp_ptr[0], sizeof(uint8_t) * 8);
        memcpy(req.DstAddr, tmp_ptr[1], sizeof(uint8_t) * 8);
        memcpy(req.Key.Keysource, tmp_ptr[2], sizeof(uint8_t) * 8);
        req.DSN_suppressed = tmp_bool[0];
        req.Key.SecurityLevel = tmp_u8[2];
        req.Key.KeyIdMode = tmp_u8[3];
        TRACE("dataInd");
        if (ctxt->mac_api.data_ind_ext_cb)
            ctxt->mac_api.data_ind_ext_cb(&ctxt->mac_api, &req, &ie_ext);
        else
            ctxt->mac_api.data_ind_cb(&ctxt->mac_api, &req);
        break;
    }
    case SPINEL_PROP_HWADDR: {
        TRACE("cnf macEui64");
        spinel_datatype_unpack_in_place(frame, sizeof(frame), "E", ctxt->hw_mac);
        ctxt->hw_addr_done = true;
        break;
    }
    // FIXME: for now, only SPINEL_PROP_WS_START return a SPINEL_PROP_LAST_STATUS
    case SPINEL_PROP_LAST_STATUS: {
        TRACE("cnf mlmeStart");
        ctxt->mac_api.mlme_conf_cb(&ctxt->mac_api, MLME_START, NULL);
        break;
    }
    default:
        WARN("not implemented");
        break;
    }
}

void rcp_rx(struct wsbr_ctxt *ctxt)
{
    uint8_t hdr;
    int cmd, prop;
    uint8_t buf[MAC_IEEE_802_15_4G_MAX_PHY_PACKET_SIZE];
    uint8_t *data;
    int len, data_len;

    len = ctxt->rcp_rx(ctxt->os_ctxt, buf, sizeof(buf));
    spinel_datatype_unpack(buf, len, "CiiD", &hdr, &cmd, &prop, &data, &data_len);

    if (cmd == SPINEL_CMD_PROP_VALUE_IS) {
        wsbr_spinel_is(ctxt, prop, data, data_len);
    } else if (cmd == SPINEL_CMD_RESET) {
        // FIXME: CMD_RESET should reply with SPINEL_PROP_LAST_STATUS ==
        // STATUS_RESET_SOFTWARE
        FATAL_ON(ctxt->reset_done, 3, "MAC layer has been reset. Operation not supported");
        ctxt->reset_done = true;
        TRACE("cnf reset");
    } else {
        WARN("not implemented: %02x", cmd);
        return;
    }
}

uint8_t wsbr_get_spinel_hdr(struct wsbr_ctxt *ctxt)
{
    uint8_t hdr = FIELD_PREP(0xC0, 0x2) | FIELD_PREP(0x30, ctxt->spinel_iid);

    ctxt->spinel_tid = (ctxt->spinel_tid + 1) % 0x10;
    if (!ctxt->spinel_tid)
        ctxt->spinel_tid = 1;
    hdr |= FIELD_PREP(0x0F, ctxt->spinel_tid);
    return hdr;
}

void wsbr_spinel_set_bool(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    uint8_t hdr = wsbr_get_spinel_hdr(ctxt);
    uint8_t frame[1 + 3 + 3 + sizeof(bool)];
    int frame_len;

    BUG_ON(data_len != sizeof(bool));

    frame_len = spinel_datatype_pack(frame, sizeof(frame), "Ciib", hdr, SPINEL_CMD_PROP_VALUE_SET, prop, *((bool *)data));
    ctxt->rcp_tx(ctxt->os_ctxt, frame, frame_len);
}

static void wsbr_spinel_set_u8(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    uint8_t hdr = wsbr_get_spinel_hdr(ctxt);
    uint8_t frame[1 + 3 + 3 + sizeof(uint8_t)];
    int frame_len;

    BUG_ON(data_len != sizeof(uint8_t));

    frame_len = spinel_datatype_pack(frame, sizeof(frame), "CiiC", hdr, SPINEL_CMD_PROP_VALUE_SET, prop, *((uint8_t *)data));
    ctxt->rcp_tx(ctxt->os_ctxt, frame, frame_len);
}

static void wsbr_spinel_set_u16(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    uint8_t hdr = wsbr_get_spinel_hdr(ctxt);
    uint8_t frame[1 + 3 + 3 + sizeof(uint16_t)];
    int frame_len;

    BUG_ON(data_len != sizeof(uint16_t));

    frame_len = spinel_datatype_pack(frame, sizeof(frame), "CiiS", hdr, SPINEL_CMD_PROP_VALUE_SET, prop, *((uint16_t *)data));
    ctxt->rcp_tx(ctxt->os_ctxt, frame, frame_len);
}

static void wsbr_spinel_set_u32(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    uint8_t hdr = wsbr_get_spinel_hdr(ctxt);
    uint8_t frame[1 + 3 + 3 + sizeof(uint32_t)];
    int frame_len;

    BUG_ON(data_len != sizeof(uint32_t));

    frame_len = spinel_datatype_pack(frame, sizeof(frame), "CiiL", hdr, SPINEL_CMD_PROP_VALUE_SET, prop, *((uint32_t *)data));
    ctxt->rcp_tx(ctxt->os_ctxt, frame, frame_len);
}

static void wsbr_spinel_set_eui64(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    uint8_t hdr = wsbr_get_spinel_hdr(ctxt);
    uint8_t frame[1 + 3 + 3 + 8];
    int frame_len;

    BUG_ON(data_len != 8);

    frame_len = spinel_datatype_pack(frame, sizeof(frame), "CiiE", hdr, SPINEL_CMD_PROP_VALUE_SET, prop, (uint8_t *)data);
    ctxt->rcp_tx(ctxt->os_ctxt, frame, frame_len);
}

static void wsbr_spinel_set_data(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    uint8_t hdr = wsbr_get_spinel_hdr(ctxt);
    uint8_t frame[256];
    int frame_len;

    frame_len = spinel_datatype_pack(frame, sizeof(frame), "CiiD", hdr, SPINEL_CMD_PROP_VALUE_SET, prop, data, data_len);
    ctxt->rcp_tx(ctxt->os_ctxt, frame, frame_len);
}

static void wsbr_spinel_set_cca_threshold(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    uint8_t frame[1];
    int frame_len;

    BUG_ON(prop != SPINEL_PROP_WS_CCA_THRESHOLD);
    BUG_ON(data_len != sizeof(uint8_t));
    frame_len = spinel_datatype_pack(frame, sizeof(frame), "d", data, data_len);
    wsbr_spinel_set_data(ctxt, SPINEL_PROP_WS_CCA_THRESHOLD_START, frame, frame_len);
}

static void wsbr_spinel_set_cca_threshold_start(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    const uint8_t *req = data;
    uint8_t frame[4];
    int frame_len;

    BUG_ON(prop != SPINEL_PROP_WS_CCA_THRESHOLD_START);
    BUG_ON(data_len != 4);
    frame_len = spinel_datatype_pack(frame, sizeof(frame), "CCCC", req[0], req[1], req[2], req[3]);
    wsbr_spinel_set_data(ctxt, SPINEL_PROP_WS_CCA_THRESHOLD_START, frame, frame_len);
}

static void wsbr_spinel_set_multi_csma_parameters(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    const struct mlme_multi_csma_ca_s *req = data;
    uint8_t frame[3];
    int frame_len;

    BUG_ON(prop != SPINEL_PROP_WS_MULTI_CSMA_PARAMETERS);
    BUG_ON(data_len != sizeof(struct mlme_multi_csma_ca_s));
    frame_len = spinel_datatype_pack(frame, sizeof(frame), "CS",
                                     req->number_of_csma_ca_periods,
                                     req->multi_cca_interval);
    wsbr_spinel_set_data(ctxt, SPINEL_PROP_WS_MULTI_CSMA_PARAMETERS, frame, frame_len);
}

static void wsbr_spinel_set_rf_configuration(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    const struct phy_rf_channel_configuration_s *req = data;
    uint8_t frame[16];
    int frame_len;

    BUG_ON(prop != SPINEL_PROP_WS_RF_CONFIGURATION);
    BUG_ON(data_len != sizeof(struct phy_rf_channel_configuration_s));
    frame_len = spinel_datatype_pack(frame, sizeof(frame), "LLLSCC",
                                     req->channel_0_center_frequency,
                                     req->channel_spacing, req->datarate,
                                     req->number_of_channels, req->modulation,
                                     req->modulation_index);
    wsbr_spinel_set_data(ctxt, SPINEL_PROP_WS_RF_CONFIGURATION, frame, frame_len);
}

static void wsbr_spinel_set_device_table(struct wsbr_ctxt *ctxt, int entry_idx, const mlme_device_descriptor_t *req)
{
    uint8_t frame[20];
    int frame_len;

    frame_len = spinel_datatype_pack(frame, sizeof(frame), "CSSELb",
                                     entry_idx, req->PANId, req->ShortAddress,
                                     req->ExtAddress, req->FrameCounter,
                                     req->Exempt);
    wsbr_spinel_set_data(ctxt, SPINEL_PROP_WS_DEVICE_TABLE, frame, frame_len);
}

static void wsbr_spinel_set_key_table(struct wsbr_ctxt *ctxt, int entry_idx,
                                      const mlme_key_descriptor_entry_t *req)
{
    uint8_t frame[128];
    int frame_len;
    int len;

    BUG_ON(req->KeyIdLookupListEntries > 1);
    BUG_ON(req->KeyUsageListEntries);
    BUG_ON(req->KeyDeviceListEntries);
    if (!req->KeyIdLookupListEntries)
        len = 0;
    else if (req->KeyIdLookupList->LookupDataSize)
        len = 9;
    else
        len = 5;

    frame_len = spinel_datatype_pack(frame, sizeof(frame), "Cdd", entry_idx,
                               req->Key, 16,
                               req->KeyIdLookupList->LookupData, len);
    wsbr_spinel_set_data(ctxt, SPINEL_PROP_WS_KEY_TABLE, frame, frame_len);
}

static void wsbr_spinel_set_frame_counter(struct wsbr_ctxt *ctxt, int counter, uint32_t val)
{
    uint8_t frame[7];
    int frame_len;

    frame_len = spinel_datatype_pack(frame, sizeof(frame), "iL", counter, val);
    wsbr_spinel_set_data(ctxt, SPINEL_PROP_WS_FRAME_COUNTER, frame, frame_len);
}

static const struct {
    const char *str;
    mlme_attr_t attr;
    void (*prop_set)(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len);
    unsigned int prop;
} mlme_prop_cstr[] = {
    { "macRxOnWhenIdle",                 macRxOnWhenIdle,                 wsbr_spinel_set_bool,                  SPINEL_PROP_WS_RX_ON_WHEN_IDLE,                  },
    { "macSecurityEnabled",              macSecurityEnabled,              wsbr_spinel_set_bool,                  SPINEL_PROP_WS_SECURITY_ENABLED,                 },
    { "macAcceptByPassUnknowDevice",     macAcceptByPassUnknowDevice,     wsbr_spinel_set_bool,                  SPINEL_PROP_WS_ACCEPT_BYPASS_UNKNOW_DEVICE,      },
    { "macEdfeForceStop",                macEdfeForceStop,                wsbr_spinel_set_bool,                  SPINEL_PROP_WS_EDFE_FORCE_STOP,                  },
    { "macAssociationPermit",            macAssociationPermit,            wsbr_spinel_set_bool,                  SPINEL_PROP_WS_ASSOCIATION_PERMIT,               },
    { "phyCurrentChannel",               phyCurrentChannel,               wsbr_spinel_set_u8,                    SPINEL_PROP_PHY_CHAN,                            },
    { "macAutoRequestKeyIdMode",         macAutoRequestKeyIdMode,         wsbr_spinel_set_u8,                    SPINEL_PROP_WS_AUTO_REQUEST_KEY_ID_MODE,         },
    { "macAutoRequestKeyIndex",          macAutoRequestKeyIndex,          wsbr_spinel_set_u8,                    SPINEL_PROP_WS_AUTO_REQUEST_KEY_INDEX,           },
    { "macAutoRequestSecurityLevel",     macAutoRequestSecurityLevel,     wsbr_spinel_set_u8,                    SPINEL_PROP_WS_AUTO_REQUEST_SECURITY_LEVEL,      },
    { "macBeaconPayloadLength",          macBeaconPayloadLength,          wsbr_spinel_set_u8,                    SPINEL_PROP_WS_BEACON_PAYLOAD_LENGTH,            },
    { "macMaxFrameRetries",              macMaxFrameRetries,              wsbr_spinel_set_u8,                    SPINEL_PROP_WS_MAX_FRAME_RETRIES,                },
    { "macTXPower",                      macTXPower,                      wsbr_spinel_set_u8,                    SPINEL_PROP_PHY_TX_POWER,                        },
    { "macPANId",                        macPANId,                        wsbr_spinel_set_u16,                   SPINEL_PROP_MAC_15_4_PANID,                      },
    { "macCoordShortAddress",            macCoordShortAddress,            wsbr_spinel_set_u16,                   SPINEL_PROP_WS_COORD_SHORT_ADDRESS,              },
    { "macShortAddress",                 macShortAddress,                 wsbr_spinel_set_u16,                   SPINEL_PROP_MAC_15_4_SADDR,                      },
    { "macDeviceDescriptionPanIDUpdate", macDeviceDescriptionPanIDUpdate, wsbr_spinel_set_u16,                   SPINEL_PROP_WS_DEVICE_DESCRIPTION_PAN_ID_UPDATE, },
    { "macAckWaitDuration",              macAckWaitDuration,              wsbr_spinel_set_u16,                   SPINEL_PROP_WS_ACK_WAIT_DURATION,                },
    { "mac802_15_4Mode",                 mac802_15_4Mode,                 wsbr_spinel_set_u32,                   SPINEL_PROP_WS_15_4_MODE,                        },
    { "macAutoRequestKeySource",         macAutoRequestKeySource,         wsbr_spinel_set_eui64,                 SPINEL_PROP_WS_AUTO_REQUEST_KEY_SOURCE,          },
    { "macCoordExtendedAddress",         macCoordExtendedAddress,         wsbr_spinel_set_eui64,                 SPINEL_PROP_WS_COORD_EXTENDED_ADDRESS,           },
    { "macDefaultKeySource",             macDefaultKeySource,             wsbr_spinel_set_eui64,                 SPINEL_PROP_WS_DEFAULT_KEY_SOURCE,               },
    { "macBeaconPayload",                macBeaconPayload,                wsbr_spinel_set_data,                  SPINEL_PROP_WS_BEACON_PAYLOAD,                   },
    { "macCCAThreshold",                 macCCAThreshold,                 wsbr_spinel_set_cca_threshold,         SPINEL_PROP_WS_CCA_THRESHOLD,                    },
    { "macCCAThresholdStart",            macCCAThresholdStart,            wsbr_spinel_set_cca_threshold_start,   SPINEL_PROP_WS_CCA_THRESHOLD_START,              },
    { "macMultiCSMAParameters",          macMultiCSMAParameters,          wsbr_spinel_set_multi_csma_parameters, SPINEL_PROP_WS_MULTI_CSMA_PARAMETERS,            },
    { "macRfConfiguration",              macRfConfiguration,              wsbr_spinel_set_rf_configuration,      SPINEL_PROP_WS_RF_CONFIGURATION,                 },
    { "macDeviceTable",                  macDeviceTable,                  NULL /* Special */,                    SPINEL_PROP_WS_DEVICE_TABLE,                     },
    { "macKeyTable",                     macKeyTable,                     NULL /* Special */,                    SPINEL_PROP_WS_KEY_TABLE,                        },
    { "macFrameCounter",                 macFrameCounter,                 NULL /* Special */,                    SPINEL_PROP_WS_FRAME_COUNTER,                    },
    { }
};

static void wsbr_mlme_set(const struct mac_api_s *api, const void *data)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    const mlme_set_t *req = data;
    int i;

    BUG_ON(!api);
    BUG_ON(api != &ctxt->mac_api);
    // SPINEL_CMD_PROP_VALUE_SET
    for (i = 0; mlme_prop_cstr[i].prop; i++)
        if (req->attr == mlme_prop_cstr[i].attr)
            break;
    TRACE("set %s", mlme_prop_cstr[i].str);
    if (mlme_prop_cstr[i].prop_set) {
        // Normally, req->attr_index == 0, but nanostack is not rigorous on that
        mlme_prop_cstr[i].prop_set(ctxt, mlme_prop_cstr[i].prop, req->value_pointer, req->value_size);
    } else if (req->attr == macDeviceTable) {
        BUG_ON(req->value_size != sizeof(mlme_device_descriptor_t));
        wsbr_spinel_set_device_table(ctxt, req->attr_index, req->value_pointer);
    } else if (req->attr == macKeyTable) {
        BUG_ON(req->value_size != sizeof(mlme_key_descriptor_entry_t));
        wsbr_spinel_set_key_table(ctxt, req->attr_index, req->value_pointer);
    } else if (req->attr == macFrameCounter) {
        BUG_ON(req->value_size != sizeof(uint32_t));
        wsbr_spinel_set_frame_counter(ctxt, req->attr_index, *(uint32_t *)req->value_pointer);
    } else {
        BUG("Unknown message");
    }
}

static void wsbr_mlme_get(const struct mac_api_s *api, const void *data)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    uint8_t hdr = wsbr_get_spinel_hdr(ctxt);
    const mlme_get_t *req = data;
    uint8_t frame[10];
    int frame_len;
    int i;

    // SPINEL_CMD_PROP_VALUE_GET
    for (i = 0; mlme_prop_cstr[i].prop; i++)
        if (req->attr == mlme_prop_cstr[i].attr)
            break;
    TRACE("get %s", mlme_prop_cstr[i].str);
    switch  (mlme_prop_cstr[i].prop) {
    case SPINEL_PROP_WS_DEVICE_TABLE:
    case SPINEL_PROP_WS_KEY_TABLE:
    case SPINEL_PROP_WS_FRAME_COUNTER:
        frame_len = spinel_datatype_pack(frame, sizeof(frame), "Ciii", hdr, SPINEL_CMD_PROP_VALUE_GET, mlme_prop_cstr[i].prop, req->attr_index);
    default:
        frame_len = spinel_datatype_pack(frame, sizeof(frame), "Ciii", hdr, SPINEL_CMD_PROP_VALUE_GET, mlme_prop_cstr[i].prop, 0);
    }
    ctxt->rcp_tx(ctxt->os_ctxt, frame, frame_len);
}

static void wsbr_mlme_scan(const struct mac_api_s *api, const void *data)
{
    WARN("not implemented");
}

static void wsbr_mlme_start(const struct mac_api_s *api, const void *data)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    const mlme_start_t *req = data;
    uint8_t frame[19];
    int frame_len;

    TRACE("mlmeStart");
    // FIXME: consider SPINEL_PROP_PHY_ENABLED
    frame_len = spinel_datatype_pack(frame, sizeof(frame), "SCCLCCb",
                                     req->PANId, req->LogicalChannel, req->ChannelPage,
                                     req->StartTime, req->BeaconOrder,
                                     req->SuperframeOrder, req->PANCoordinator);
    wsbr_spinel_set_data(ctxt, SPINEL_PROP_WS_START, frame, frame_len);
}

static void wsbr_mlme_reset(const struct mac_api_s *api, const void *data)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    const mlme_reset_t *req = data;

    TRACE("mlmeReset");
    // SPINEL_CMD_RESET or SPINEL_PROP_PHY_ENABLED
    // It seems that SPINEL_CMD_RESET is too wide. It reset the whole device
    wsbr_spinel_set_bool(ctxt, SPINEL_PROP_WS_RESET, &req->SetDefaultPIB, sizeof(bool));
}

void wsbr_mlme(const struct mac_api_s *api, mlme_primitive id, const void *data)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    static const struct {
        uint32_t    val;
        void (*fn)(const struct mac_api_s *, const void *);
    } table[] = {
        { MLME_GET,           wsbr_mlme_get },
        { MLME_SET,           wsbr_mlme_set },
        { MLME_SCAN,          wsbr_mlme_scan },
        { MLME_START,         wsbr_mlme_start },
        { MLME_RESET,         wsbr_mlme_reset },
        // Never used
        { MLME_POLL,          NULL }, // Only used with Thread?
        { MLME_ASSOCIATE,     NULL },
        { MLME_DISASSOCIATE,  NULL },
        { MLME_RX_ENABLE,     NULL },
        { MLME_SYNC,          NULL },
        { MLME_GTS,           NULL },
        // These ones only make sense with mlme_ind_cb()
        { MLME_BEACON_NOTIFY, NULL },
        { MLME_ORPHAN,        NULL },
        { MLME_COMM_STATUS,   NULL },
        { MLME_SYNC_LOSS,     NULL },
        { -1, },
    };
    int i;

    BUG_ON(!api);
    BUG_ON(&ctxt->mac_api != api);
    for (i = 0; table[i].val != -1; i++)
        if (id == table[i].val)
            break;
    if (!table[i].fn)
        WARN("Try to reach unexpected API: id");
    else
        table[i].fn(api, data);
}

void wsbr_mcps_req_ext(const struct mac_api_s *api,
                       const struct mcps_data_req_s *data,
                       const struct mcps_data_req_ie_list *ie_ext,
                       const struct channel_list_s *async_channel_list)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    uint8_t hdr = wsbr_get_spinel_hdr(ctxt);
    const struct channel_list_s default_chan_list = {
        .channel_page = CHANNEL_PAGE_UNDEFINED,
    };
    uint8_t frame[2048];
    int frame_len;
    int total, i, ret;

    BUG_ON(!api);
    BUG_ON(&ctxt->mac_api != api);
    BUG_ON(!ie_ext);
    BUG_ON(data->TxAckReq && async_channel_list);
    TRACE("mcpsReq");
    if (!async_channel_list)
        async_channel_list = &default_chan_list;
    frame_len = spinel_datatype_pack(frame, sizeof(frame), "CiidCCSECbbbbbbCCCEid",
                                     hdr, SPINEL_CMD_PROP_VALUE_SET, SPINEL_PROP_STREAM_RAW,
                                     data->msdu, data->msduLength,
                                     data->SrcAddrMode, data->DstAddrMode,
                                     data->DstPANId, data->DstAddr,
                                     data->msduHandle, data->TxAckReq,
                                     data->InDirectTx, data->PendingBit,
                                     data->SeqNumSuppressed, data->PanIdSuppressed,
                                     data->ExtendedFrameExchange,
                                     data->Key.SecurityLevel, data->Key.KeyIdMode,
                                     data->Key.KeyIndex, data->Key.Keysource,
                                     async_channel_list->channel_page,
                                     async_channel_list->channel_mask,
                                     sizeof(async_channel_list->channel_mask));
    total = 0;
    for (i = 0; i < ie_ext->payloadIovLength; i++)
        total += ie_ext->payloadIeVectorList[i].iovLen;
    ret = spinel_datatype_pack(frame + frame_len, sizeof(frame) - frame_len,
                               SPINEL_DATATYPE_UINT16_S, total);
    BUG_ON(ret < 0);
    frame_len += ret;
    for (i = 0; i < ie_ext->payloadIovLength; i++) {
        memcpy(frame + frame_len,
               ie_ext->payloadIeVectorList[i].ieBase,
               ie_ext->payloadIeVectorList[i].iovLen);
        frame_len += ie_ext->payloadIeVectorList[i].iovLen;
    }

    total = 0;
    for (i = 0; i < ie_ext->headerIovLength; i++)
        total += ie_ext->headerIeVectorList[i].iovLen;
    ret = spinel_datatype_pack(frame + frame_len, sizeof(frame) - frame_len,
                               SPINEL_DATATYPE_UINT16_S, total);
    BUG_ON(ret < 0);
    frame_len += ret;
    for (i = 0; i < ie_ext->headerIovLength; i++) {
        memcpy(frame + frame_len,
               ie_ext->headerIeVectorList[i].ieBase,
               ie_ext->headerIeVectorList[i].iovLen);
        frame_len += ie_ext->headerIeVectorList[i].iovLen;
    }
    BUG_ON(frame_len > sizeof(frame));
    ctxt->rcp_tx(ctxt->os_ctxt, frame, frame_len);
}

void wsbr_mcps_req(const struct mac_api_s *api,
                   const struct mcps_data_req_s *data)
{
    return wsbr_mcps_req_ext(api, data, NULL, NULL);
}

uint8_t wsbr_mcps_purge(const struct mac_api_s *api,
                        const struct mcps_purge_s *data)
{
    struct mcps_purge_conf_s conf = {
        .msduHandle = data->msduHandle,
    };

    BUG_ON(!api);
    WARN("not implemented");
    api->purge_conf_cb(api, &conf);
    return 0;
}

int8_t wsbr_mac_addr_set(const struct mac_api_s *api, const uint8_t *mac64)
{
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);

    BUG_ON(!api);
    BUG_ON(!mac64);

    memcpy(ctxt->dynamic_mac, mac64, 8);
    return 0;
}

int8_t wsbr_mac_addr_get(const struct mac_api_s *api,
                     mac_extended_address_type type, uint8_t *mac64)
{
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);

    BUG_ON(!api);
    BUG_ON(!mac64);

    switch (type) {
    case MAC_EXTENDED_READ_ONLY:
        memcpy(mac64, ctxt->hw_mac, 8);
        return 0;
    case MAC_EXTENDED_DYNAMIC:
        memcpy(mac64, ctxt->dynamic_mac, 8);
        return 0;
    default:
        BUG("Unknown address_type: %d", type);
        return -1;
    }
}

int8_t wsbr_mac_storage_sizes_get(const struct mac_api_s *api,
                                  struct mac_description_storage_size_s *buffer)
{
    BUG_ON(!api);
    BUG_ON(!buffer);

    // These values are taken from mac_description_storage_size_t
    // FIXME: we have plenty of memory, increase these values
    buffer->device_decription_table_size = 32;
    buffer->key_description_table_size = 4;
    buffer->key_lookup_size = 1;
    buffer->key_usage_size = 3;

    return 0;
}

int8_t wsbr_mac_mcps_ext_init(struct mac_api_s *api,
                              mcps_data_indication_ext *data_ind_cb,
                              mcps_data_confirm_ext *data_cnf_cb,
                              mcps_ack_data_req_ext *ack_data_req_cb)
{
    BUG_ON(!api);

    api->data_conf_ext_cb = data_cnf_cb;
    api->data_ind_ext_cb = data_ind_cb;
    api->enhanced_ack_data_req_cb = ack_data_req_cb;
    return 0;
}

int8_t wsbr_mac_edfe_ext_init(struct mac_api_s *api,
                              mcps_edfe_handler *edfe_ind_cb)
{
    BUG_ON(!api);

    api->edfe_ind_cb = edfe_ind_cb;
    return 0;
}

int8_t wsbr_mac_init(struct mac_api_s *api,
                     mcps_data_confirm *data_conf_cb,
                     mcps_data_indication *data_ind_cb,
                     mcps_purge_confirm *purge_conf_cb,
                     mlme_confirm *mlme_conf_cb,
                     mlme_indication *mlme_ind_cb,
                     int8_t parent_id)
{
    BUG_ON(!api);

    api->data_conf_cb = data_conf_cb;
    api->data_ind_cb = data_ind_cb;
    api->purge_conf_cb = purge_conf_cb;
    api->mlme_conf_cb = mlme_conf_cb;
    api->mlme_ind_cb = mlme_ind_cb;
    api->parent_id = parent_id;
    return 0;
}
