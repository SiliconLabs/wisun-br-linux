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
#include "host-net/dbus.h"
#include "host-common/utils.h"
#include "host-common/spinel.h"
#include "host-common/spinel_buffer.h"
#include "host-common/log.h"

static void adjust_rcp_time_diff(struct wsbr_ctxt *ctxt, uint32_t rcp_time)
{
    struct timespec tp;
    int rcp_time_diff;

    // FIXME: explain hy and when this case happens
    if (!rcp_time)
        return;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    rcp_time_diff = (tp.tv_sec * 1000000 + tp.tv_nsec / 1000) - rcp_time;
    if (!ctxt->rcp_time_diff)
        ctxt->rcp_time_diff = rcp_time_diff;
    rcp_time_diff = rcp_time_diff * 0.10 + ctxt->rcp_time_diff * 0.9; // smooth adjustement
    ctxt->rcp_time_diff = rcp_time_diff;
}

static void wsbr_spinel_is(struct wsbr_ctxt *ctxt, int prop, struct spinel_buffer *buf)
{
    switch (prop) {
    case SPINEL_PROP_WS_DEVICE_TABLE: {
        struct mlme_device_descriptor_s data;
        mlme_get_conf_t req = {
            .attr = macDeviceTable,
            .value_pointer = &data,
            .value_size = sizeof(data),
        };

        req.attr_index    = spinel_pop_int(buf);
        data.PANId        = spinel_pop_u16(buf);
        data.ShortAddress = spinel_pop_u16(buf);
        spinel_pop_fixed_u8_array(buf, data.ExtAddress, 8);
        data.FrameCounter = spinel_pop_u32(buf);
        data.Exempt       = spinel_pop_bool(buf);
        BUG_ON(spinel_remaining_size(buf));
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

        req.attr_index = spinel_pop_int(buf);
        data           = spinel_pop_u32(buf);
        BUG_ON(spinel_remaining_size(buf));
        ctxt->mac_api.mlme_conf_cb(&ctxt->mac_api, MLME_GET, &req);
        break;
    }
    case SPINEL_PROP_WS_CCA_THRESHOLD: {
        mlme_get_conf_t req = {
            .attr = macCCAThreshold,
        };

        req.value_size = spinel_pop_data_ptr(buf, (uint8_t **)&req.value_pointer);
        BUG_ON(spinel_remaining_size(buf));
        ctxt->mac_api.mlme_conf_cb(&ctxt->mac_api, MLME_GET, &req);
        break;
    }
    case SPINEL_PROP_WS_MLME_IND: {
        int id;
        uint8_t *data;

        id = spinel_pop_int(buf);
        spinel_pop_data_ptr(buf, &data);
        BUG_ON(spinel_remaining_size(buf));
        ctxt->mac_api.mlme_ind_cb(&ctxt->mac_api, id, data);
        break;
    }
    case SPINEL_PROP_WS_MCPS_DROP: {
        struct mcps_purge_conf_s req = { };

        req.msduHandle = spinel_pop_u8(buf);
        ctxt->mac_api.purge_conf_cb(&ctxt->mac_api, &req);
        break;
    }
    case SPINEL_PROP_STREAM_STATUS: {
        mcps_data_conf_t req = { };
        mcps_data_conf_payload_t conf_req = { };

        req.status      = spinel_pop_u8(buf);
        req.msduHandle  = spinel_pop_u8(buf);
        req.timestamp   = spinel_pop_u32(buf);
        req.cca_retries = spinel_pop_u8(buf);
        req.tx_retries  = spinel_pop_u8(buf);
        conf_req.headerIeListLength  = spinel_pop_data_ptr(buf, &conf_req.headerIeList);
        conf_req.payloadIeListLength = spinel_pop_data_ptr(buf, &conf_req.payloadIeList);
        conf_req.payloadLength       = spinel_pop_data_ptr(buf, &conf_req.payloadPtr);
        BUG_ON(spinel_remaining_size(buf));
        adjust_rcp_time_diff(ctxt, req.timestamp);
        // Note: we don't support data_conf_cb()
        ctxt->mac_api.data_conf_ext_cb(&ctxt->mac_api, &req, &conf_req);
        break;
    }
    case SPINEL_PROP_STREAM_RAW: {
        mcps_data_ind_t req = { };
        mcps_data_ie_list_t ie_ext = { };

        req.msduLength             = spinel_pop_data_ptr(buf, &req.msdu_ptr);
        req.SrcAddrMode            = spinel_pop_u8(buf);
        req.SrcPANId               = spinel_pop_u16(buf);
        spinel_pop_fixed_u8_array(buf, req.SrcAddr, 8);
        req.DstAddrMode            = spinel_pop_u8(buf);
        req.DstPANId               = spinel_pop_u16(buf);
        spinel_pop_fixed_u8_array(buf, req.DstAddr, 8);
        req.mpduLinkQuality        = spinel_pop_u8(buf);
        req.signal_dbm             = spinel_pop_i8(buf);
        req.timestamp              = spinel_pop_u32(buf);
        req.DSN_suppressed         = spinel_pop_bool(buf);
        req.DSN                    = spinel_pop_u8(buf);
        req.Key.SecurityLevel      = spinel_pop_u8(buf);
        req.Key.KeyIdMode          = spinel_pop_u8(buf);
        req.Key.KeyIndex           = spinel_pop_u8(buf);
        spinel_pop_fixed_u8_array(buf, req.Key.Keysource, 8);
        ie_ext.headerIeListLength  = spinel_pop_data_ptr(buf, &ie_ext.headerIeList);
        ie_ext.payloadIeListLength = spinel_pop_data_ptr(buf, &ie_ext.payloadIeList);
        BUG_ON(spinel_remaining_size(buf));
        adjust_rcp_time_diff(ctxt, req.timestamp);
        // Note: we don't support data_ind_cb()
        ctxt->mac_api.data_ind_ext_cb(&ctxt->mac_api, &req, &ie_ext);
        break;
    }
    case SPINEL_PROP_HWADDR: {
        spinel_pop_fixed_u8_array(buf, ctxt->hw_mac, 8);
        BUG_ON(spinel_remaining_size(buf));
        ctxt->hw_addr_done = true;
        break;
    }
    // FIXME: for now, only SPINEL_PROP_WS_START return a SPINEL_PROP_LAST_STATUS
    case SPINEL_PROP_LAST_STATUS: {
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
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(MAC_IEEE_802_15_4G_MAX_PHY_PACKET_SIZE + 70);
    int cmd, prop;

    buf->len = ctxt->rcp_rx(ctxt->os_ctxt, buf->frame, buf->len);
    if (!buf->len)
        return;
    spinel_pop_u8(buf); /* packet header */
    cmd = spinel_pop_int(buf);

    if (cmd == SPINEL_CMD_NOOP) {
        /* empty */
    } else if (cmd == SPINEL_CMD_PROP_VALUE_IS) {
        prop = spinel_pop_int(buf);
        wsbr_spinel_is(ctxt, prop, buf);
    } else if (cmd == SPINEL_CMD_RESET) {
        const char *version_fw_str;

        if (spinel_remaining_size(buf) < 16)
            FATAL(1, "unknown RESET format (bad firmware?)");
        // FIXME: CMD_RESET should reply with SPINEL_PROP_LAST_STATUS ==
        // STATUS_RESET_SOFTWARE
        ctxt->rcp_version_api = spinel_pop_u32(buf);
        ctxt->rcp_version_fw = spinel_pop_u32(buf);
        version_fw_str = spinel_pop_str(buf);
        spinel_pop_bool(buf); // is_hw_reset is no more used
        ctxt->storage_sizes.device_decription_table_size = spinel_pop_u8(buf);
        ctxt->storage_sizes.key_description_table_size = spinel_pop_u8(buf);
        ctxt->storage_sizes.key_lookup_size = spinel_pop_u8(buf);
        ctxt->storage_sizes.key_usage_size = spinel_pop_u8(buf);
        wsbr_handle_reset(ctxt, version_fw_str);
    } else {
        WARN("%s: not implemented: %02x", __func__, cmd);
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

void spinel_push_hdr_set_prop(struct wsbr_ctxt *ctxt, struct spinel_buffer *buf, unsigned int prop)
{
    spinel_push_u8(buf, wsbr_get_spinel_hdr(ctxt));
    spinel_push_int(buf, SPINEL_CMD_PROP_VALUE_SET);
    spinel_push_int(buf, prop);
}

void spinel_push_hdr_get_prop(struct wsbr_ctxt *ctxt, struct spinel_buffer *buf, unsigned int prop)
{
    spinel_push_u8(buf, wsbr_get_spinel_hdr(ctxt));
    spinel_push_int(buf, SPINEL_CMD_PROP_VALUE_GET);
    spinel_push_int(buf, prop);
}

void wsbr_spinel_set_bool(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + sizeof(bool));

    BUG_ON(data_len != sizeof(bool));
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_bool(buf, *(bool *)data);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

static void wsbr_spinel_set_u8(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + sizeof(uint8_t));

    BUG_ON(data_len != sizeof(uint8_t));
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_u8(buf, *(uint8_t *)data);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

static void wsbr_spinel_set_u16(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + sizeof(uint16_t));

    BUG_ON(data_len != sizeof(uint16_t));
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_u16(buf, *(uint16_t *)data);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

static void wsbr_spinel_set_u32(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + sizeof(uint32_t));

    BUG_ON(data_len != sizeof(uint32_t));
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_u32(buf, *(uint32_t *)data);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

static void wsbr_spinel_set_eui64(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 8);

    BUG_ON(data_len != 8);
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_fixed_u8_array(buf, data, 8);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

static void wsbr_spinel_set_data(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 256);

    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_raw(buf, data, data_len);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

static void wsbr_spinel_set_cca_threshold_start(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 4);
    const uint8_t *req = data;

    BUG_ON(prop != SPINEL_PROP_WS_CCA_THRESHOLD_START);
    BUG_ON(data_len != 4);
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_fixed_u8_array(buf, req, 4);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

static void wsbr_spinel_set_multi_csma_parameters(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 1 + 2);
    const struct mlme_multi_csma_ca_s *req = data;

    BUG_ON(prop != SPINEL_PROP_WS_MULTI_CSMA_PARAMETERS);
    BUG_ON(data_len != sizeof(struct mlme_multi_csma_ca_s));
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_u8(buf,  req->number_of_csma_ca_periods);
    spinel_push_u16(buf, req->multi_cca_interval);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

static void wsbr_spinel_set_rf_configuration(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 16);
    const struct phy_rf_channel_configuration_s *req = data;

    BUG_ON(prop != SPINEL_PROP_WS_RF_CONFIGURATION);
    BUG_ON(data_len != sizeof(struct phy_rf_channel_configuration_s));
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_u32(buf, req->channel_0_center_frequency);
    spinel_push_u32(buf, req->channel_spacing);
    spinel_push_u32(buf, req->datarate);
    spinel_push_u16(buf, req->number_of_channels);
    spinel_push_u8(buf,  req->modulation);
    spinel_push_u8(buf,  req->modulation_index);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

static void wsbr_spinel_set_request_restart(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 16);
    const struct mlme_request_restart_config_s *req = data;

    BUG_ON(prop != SPINEL_PROP_WS_REQUEST_RESTART);
    BUG_ON(data_len != sizeof(struct mlme_request_restart_config_s));
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_u8(buf,  req->cca_failure_restart_max);
    spinel_push_u8(buf,  req->tx_failure_restart_max);
    spinel_push_u16(buf, req->blacklist_min_ms);
    spinel_push_u16(buf, req->blacklist_max_ms);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

static void wsbr_spinel_set_mac_filter_start(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 8);
    const mlme_request_mac_filter_start_t *req = data;

    BUG_ON(prop != SPINEL_PROP_WS_MAC_FILTER_START);
    BUG_ON(data_len != sizeof(mlme_request_mac_filter_start_t));
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_u16(buf, req->lqi_m);
    spinel_push_u16(buf, req->lqi_add);
    spinel_push_u16(buf, req->dbm_m);
    spinel_push_u16(buf, req->dbm_add);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

static void wsbr_spinel_set_mac_filter_clear(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3);

    BUG_ON(prop != SPINEL_PROP_WS_MAC_FILTER_CLEAR);
    BUG_ON(data_len != 0);
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

static void wsbr_spinel_set_mac_filter_add_long(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 16);
    const mlme_request_mac_filter_add_long_t *req = data;

    BUG_ON(prop != SPINEL_PROP_WS_MAC_FILTER_ADD_LONG);
    BUG_ON(data_len != sizeof(mlme_request_mac_filter_add_long_t));
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_fixed_u8_array(buf, req->mac64, 8);
    spinel_push_u16(buf, req->lqi_m);
    spinel_push_u16(buf, req->lqi_add);
    spinel_push_u16(buf, req->dbm_m);
    spinel_push_u16(buf, req->dbm_add);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

static void wsbr_spinel_set_mac_filter_stop(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3);

    BUG_ON(prop != SPINEL_PROP_WS_MAC_FILTER_STOP);
    BUG_ON(data_len != 0);
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

static void wsbr_spinel_set_device_table(struct wsbr_ctxt *ctxt, int entry_idx, const mlme_device_descriptor_t *req)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 20);

    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_DEVICE_TABLE);
    spinel_push_u8(buf,   entry_idx);
    spinel_push_u16(buf,  req->PANId);
    spinel_push_u16(buf,  req->ShortAddress);
    spinel_push_fixed_u8_array(buf, req->ExtAddress, 8);
    spinel_push_u32(buf,  req->FrameCounter);
    spinel_push_bool(buf, req->Exempt);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

static void wsbr_spinel_set_key_table(struct wsbr_ctxt *ctxt, int entry_idx,
                                      const mlme_key_descriptor_entry_t *req)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 32);
    int lookup_len;

    BUG_ON(sizeof(req->Key) != 16);
    BUG_ON(req->KeyIdLookupListEntries > 1);
    BUG_ON(req->KeyUsageListEntries);
    BUG_ON(req->KeyDeviceListEntries);
    if (!req->KeyIdLookupListEntries)
        lookup_len = 0;
    else if (req->KeyIdLookupList->LookupDataSize)
        lookup_len = 9;
    else
        lookup_len = 5;

    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_KEY_TABLE);
    spinel_push_u8(buf, entry_idx);
    spinel_push_fixed_u8_array(buf, req->Key, 16);
    spinel_push_data(buf, req->KeyIdLookupList->LookupData, lookup_len);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
    dbus_emit_keys_change(ctxt);
}

static void wsbr_spinel_set_frame_counter(struct wsbr_ctxt *ctxt, int counter, uint32_t val)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 7);

    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_FRAME_COUNTER);
    spinel_push_int(buf, counter);
    spinel_push_u32(buf, val);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

void wsbr_rcp_reset(struct wsbr_ctxt *ctxt)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3);

    spinel_push_u8(buf, wsbr_get_spinel_hdr(ctxt));
    spinel_push_int(buf, SPINEL_CMD_RESET);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

void wsbr_rcp_get_hw_addr(struct wsbr_ctxt *ctxt)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 3);

    spinel_push_hdr_get_prop(ctxt, buf, SPINEL_PROP_HWADDR);
    spinel_push_int(buf, 0);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

static const struct {
    mlme_attr_t attr;
    void (*prop_set)(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len);
    unsigned int prop;
} mlme_prop_cstr[] = {
    { macRxOnWhenIdle,                 wsbr_spinel_set_bool,                  SPINEL_PROP_WS_RX_ON_WHEN_IDLE,                  },
    { macSecurityEnabled,              wsbr_spinel_set_bool,                  SPINEL_PROP_WS_SECURITY_ENABLED,                 },
    { macAcceptByPassUnknowDevice,     wsbr_spinel_set_bool,                  SPINEL_PROP_WS_ACCEPT_BYPASS_UNKNOW_DEVICE,      },
    { macEdfeForceStop,                wsbr_spinel_set_bool,                  SPINEL_PROP_WS_EDFE_FORCE_STOP,                  },
    { macAssociationPermit,            wsbr_spinel_set_bool,                  SPINEL_PROP_WS_ASSOCIATION_PERMIT,               },
    { phyCurrentChannel,               wsbr_spinel_set_u8,                    SPINEL_PROP_PHY_CHAN,                            },
    { macAutoRequestKeyIdMode,         wsbr_spinel_set_u8,                    SPINEL_PROP_WS_AUTO_REQUEST_KEY_ID_MODE,         },
    { macAutoRequestKeyIndex,          wsbr_spinel_set_u8,                    SPINEL_PROP_WS_AUTO_REQUEST_KEY_INDEX,           },
    { macAutoRequestSecurityLevel,     wsbr_spinel_set_u8,                    SPINEL_PROP_WS_AUTO_REQUEST_SECURITY_LEVEL,      },
    { macBeaconPayloadLength,          wsbr_spinel_set_u8,                    SPINEL_PROP_WS_BEACON_PAYLOAD_LENGTH,            },
    { macMaxFrameRetries,              wsbr_spinel_set_u8,                    SPINEL_PROP_WS_MAX_FRAME_RETRIES,                },
    { macTXPower,                      wsbr_spinel_set_u8,                    SPINEL_PROP_PHY_TX_POWER,                        },
    { macMaxCSMABackoffs,              wsbr_spinel_set_u8,                    SPINEL_PROP_WS_MAX_CSMA_BACKOFFS,                },
    { macMinBE,                        wsbr_spinel_set_u8,                    SPINEL_PROP_WS_MIN_BE,                           },
    { macMaxBE,                        wsbr_spinel_set_u8,                    SPINEL_PROP_WS_MAX_BE,                           },
    { macCCAThreshold,                 wsbr_spinel_set_u8,                    SPINEL_PROP_WS_CCA_THRESHOLD,                    },
    { macPANId,                        wsbr_spinel_set_u16,                   SPINEL_PROP_MAC_15_4_PANID,                      },
    { macCoordShortAddress,            wsbr_spinel_set_u16,                   SPINEL_PROP_WS_COORD_SHORT_ADDRESS,              },
    { macShortAddress,                 wsbr_spinel_set_u16,                   SPINEL_PROP_MAC_15_4_SADDR,                      },
    { macDeviceDescriptionPanIDUpdate, wsbr_spinel_set_u16,                   SPINEL_PROP_WS_DEVICE_DESCRIPTION_PAN_ID_UPDATE, },
    { macAckWaitDuration,              wsbr_spinel_set_u16,                   SPINEL_PROP_WS_ACK_WAIT_DURATION,                },
    { mac802_15_4Mode,                 wsbr_spinel_set_u32,                   SPINEL_PROP_WS_15_4_MODE,                        },
    { macAutoRequestKeySource,         wsbr_spinel_set_eui64,                 SPINEL_PROP_WS_AUTO_REQUEST_KEY_SOURCE,          },
    { macCoordExtendedAddress,         wsbr_spinel_set_eui64,                 SPINEL_PROP_WS_COORD_EXTENDED_ADDRESS,           },
    { macDefaultKeySource,             wsbr_spinel_set_eui64,                 SPINEL_PROP_WS_DEFAULT_KEY_SOURCE,               },
    { macBeaconPayload,                wsbr_spinel_set_data,                  SPINEL_PROP_WS_BEACON_PAYLOAD,                   },
    { macCCAThresholdStart,            wsbr_spinel_set_cca_threshold_start,   SPINEL_PROP_WS_CCA_THRESHOLD_START,              },
    { macMultiCSMAParameters,          wsbr_spinel_set_multi_csma_parameters, SPINEL_PROP_WS_MULTI_CSMA_PARAMETERS,            },
    { macRfConfiguration,              wsbr_spinel_set_rf_configuration,      SPINEL_PROP_WS_RF_CONFIGURATION,                 },
    { macRequestRestart,               wsbr_spinel_set_request_restart,       SPINEL_PROP_WS_REQUEST_RESTART,                  },
    { macFilterStart,                  wsbr_spinel_set_mac_filter_start,      SPINEL_PROP_WS_MAC_FILTER_START,                 },
    { macFilterClear,                  wsbr_spinel_set_mac_filter_clear,      SPINEL_PROP_WS_MAC_FILTER_CLEAR,                 },
    { macFilterAddLong,                wsbr_spinel_set_mac_filter_add_long,   SPINEL_PROP_WS_MAC_FILTER_ADD_LONG,              },
    { macFilterStop,                   wsbr_spinel_set_mac_filter_stop,       SPINEL_PROP_WS_MAC_FILTER_STOP,                  },
    { macDeviceTable,                  NULL /* Special */,                    SPINEL_PROP_WS_DEVICE_TABLE,                     },
    { macKeyTable,                     NULL /* Special */,                    SPINEL_PROP_WS_KEY_TABLE,                        },
    { macFrameCounter,                 NULL /* Special */,                    SPINEL_PROP_WS_FRAME_COUNTER,                    },
    { }
};

static void wsbr_mlme_set(const struct mac_api_s *api, const void *data)
{
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);
    const mlme_set_t *req = data;
    int i;

    BUG_ON(!api);
    BUG_ON(ctxt != &g_ctxt);
    // SPINEL_CMD_PROP_VALUE_SET
    for (i = 0; mlme_prop_cstr[i].prop; i++)
        if (req->attr == mlme_prop_cstr[i].attr)
            break;
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
        WARN("unknown message: %02x", req->attr);
    }
}

static void wsbr_mlme_get(const struct mac_api_s *api, const void *data)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 3);
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);
    const mlme_get_t *req = data;
    int i, index = 0;

    BUG_ON(!api);
    BUG_ON(ctxt != &g_ctxt);
    for (i = 0; mlme_prop_cstr[i].prop; i++)
        if (req->attr == mlme_prop_cstr[i].attr)
            break;
    if (mlme_prop_cstr[i].prop == SPINEL_PROP_WS_DEVICE_TABLE ||
        mlme_prop_cstr[i].prop == SPINEL_PROP_WS_KEY_TABLE ||
        mlme_prop_cstr[i].prop == SPINEL_PROP_WS_FRAME_COUNTER)
        index = req->attr_index;

    spinel_push_hdr_get_prop(ctxt, buf, mlme_prop_cstr[i].prop);
    spinel_push_int(buf, index);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

static void wsbr_mlme_scan(const struct mac_api_s *api, const void *data)
{
    WARN("%s: not implemented", __func__);
}

static void wsbr_mlme_start(const struct mac_api_s *api, const void *data)
{
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 20);
    const mlme_start_t *req = data;

    BUG_ON(!api);
    BUG_ON(ctxt != &g_ctxt);
    // FIXME: consider SPINEL_PROP_PHY_ENABLED
    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_START);
    spinel_push_u16(buf,  req->PANId);
    spinel_push_u8(buf,   req->LogicalChannel);
    spinel_push_u8(buf,   req->ChannelPage);
    spinel_push_u32(buf,  req->StartTime);
    spinel_push_u8(buf,   req->BeaconOrder);
    spinel_push_u8(buf,   req->SuperframeOrder);
    spinel_push_bool(buf, req->PANCoordinator);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

static void wsbr_mlme_reset(const struct mac_api_s *api, const void *data)
{
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);
    const mlme_reset_t *req = data;

    BUG_ON(!api);
    BUG_ON(ctxt != &g_ctxt);
    // SPINEL_CMD_RESET or SPINEL_PROP_PHY_ENABLED
    // It seems that SPINEL_CMD_RESET is too wide. It reset the whole device
    wsbr_spinel_set_bool(ctxt, SPINEL_PROP_WS_RESET, &req->SetDefaultPIB, sizeof(bool));
}

void wsbr_mlme(const struct mac_api_s *api, mlme_primitive id, const void *data)
{
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);
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
    BUG_ON(ctxt != &g_ctxt);
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
                       const struct channel_list_s *async_channel_list,
                       mac_data_priority_t priority, uint8_t phy_id)
{
    const struct channel_list_s default_chan_list = {
        .channel_page = CHANNEL_PAGE_UNDEFINED,
    };
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + MAC_IEEE_802_15_4G_MAX_PHY_PACKET_SIZE);
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);
    int total, i;

    BUG_ON(ctxt != &g_ctxt);
    BUG_ON(data->TxAckReq && async_channel_list);
    BUG_ON(!ie_ext);
    if (!async_channel_list)
        async_channel_list = &default_chan_list;

    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_STREAM_RAW);
    spinel_push_data(buf, data->msdu, data->msduLength);
    spinel_push_u8(buf,   data->SrcAddrMode);
    spinel_push_u8(buf,   data->DstAddrMode);
    spinel_push_u16(buf,  data->DstPANId);
    spinel_push_fixed_u8_array(buf, data->DstAddr, 8);
    spinel_push_u8(buf,   data->msduHandle);
    spinel_push_bool(buf, data->TxAckReq);
    spinel_push_bool(buf, data->InDirectTx);
    spinel_push_bool(buf, data->PendingBit);
    spinel_push_bool(buf, data->SeqNumSuppressed);
    spinel_push_bool(buf, data->PanIdSuppressed);
    spinel_push_bool(buf, data->ExtendedFrameExchange);
    spinel_push_u8(buf,   data->Key.SecurityLevel);
    spinel_push_u8(buf,   data->Key.KeyIdMode);
    spinel_push_u8(buf,   data->Key.KeyIndex);
    spinel_push_fixed_u8_array(buf, data->Key.Keysource, 8);
    spinel_push_u16(buf,  priority);
    spinel_push_int(buf,  async_channel_list->channel_page);
    spinel_push_fixed_u32_array(buf, async_channel_list->channel_mask, 8);

    total = 0;
    for (i = 0; i < ie_ext->payloadIovLength; i++)
        total += ie_ext->payloadIeVectorList[i].iovLen;
    spinel_push_u16(buf, total);
    for (i = 0; i < ie_ext->payloadIovLength; i++)
        spinel_push_raw(buf, ie_ext->payloadIeVectorList[i].ieBase,
                        ie_ext->payloadIeVectorList[i].iovLen);

    total = 0;
    for (i = 0; i < ie_ext->headerIovLength; i++)
        total += ie_ext->headerIeVectorList[i].iovLen;
    spinel_push_u16(buf, total);
    for (i = 0; i < ie_ext->headerIovLength; i++)
        spinel_push_raw(buf, ie_ext->headerIeVectorList[i].ieBase,
                        ie_ext->headerIeVectorList[i].iovLen);
    // FIXME: also push phy_id

    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

void wsbr_mcps_req(const struct mac_api_s *api,
                   const struct mcps_data_req_s *data)
{
    return wsbr_mcps_req_ext(api, data, NULL, NULL, MAC_DATA_NORMAL_PRIORITY, 0);
}

uint8_t wsbr_mcps_purge(const struct mac_api_s *api,
                        const struct mcps_purge_s *data)
{
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 1);
    struct mcps_purge_conf_s conf = {
        .msduHandle = data->msduHandle,
    };

    BUG_ON(!api);
    BUG_ON(ctxt != &g_ctxt);
    if (!fw_api_older_than(ctxt, 0, 4, 0)) {
        spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_MCPS_DROP);
        spinel_push_u8(buf, data->msduHandle);
        ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
    } else {
        api->purge_conf_cb(api, &conf);
    }
    return 0;
}

int8_t wsbr_mac_addr_set(const struct mac_api_s *api, const uint8_t *mac64)
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

int8_t wsbr_mac_addr_get(const struct mac_api_s *api,
                     mac_extended_address_type type, uint8_t *mac64)
{
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);

    BUG_ON(!api);
    BUG_ON(!mac64);
    BUG_ON(ctxt != &g_ctxt);

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
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);

    BUG_ON(!api);
    BUG_ON(!buffer);
    BUG_ON(ctxt != &g_ctxt);

    memcpy(buffer, &ctxt->storage_sizes, sizeof(struct mac_description_storage_size_s));
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

int8_t wsbr_mac_mode_switch_resolver_set(mac_api_t *api,
                                         mode_switch_resolver *mode_resolver_cb,
                                         uint8_t base_phy_mode)
{
    BUG_ON(!api);

    WARN("%s: Not implemented", __func__);
    return 0;
}
