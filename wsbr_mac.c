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

static uint8_t wsbr_get_spinel_hdr(struct wsbr_ctxt *ctxt)
{
    uint8_t hdr = FIELD_PREP(0xC0, 0x2) | FIELD_PREP(0x30, ctxt->spinel_iid);

    ctxt->spinel_tid = (ctxt->spinel_tid + 1) % 0x10;
    if (!ctxt->spinel_tid)
        ctxt->spinel_tid = 1;
    hdr |= FIELD_PREP(0x0F, ctxt->spinel_tid);
    return hdr;
}

static void wsbr_spinel_set_bool(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
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

static const struct {
    const char *str;
    mlme_attr_t attr;
    void (*prop_set)(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len);
    unsigned int prop;
} mlme_prop_cstr[] = {
    { "macRxOnWhenIdle",                macRxOnWhenIdle,                 wsbr_spinel_set_bool,                   SPINEL_PROP_WS_RX_ON_WHEN_IDLE,                  }, 
    { "macSecurityEnabled",             macSecurityEnabled,              wsbr_spinel_set_bool,                   SPINEL_PROP_WS_SECURITY_ENABLED,                 },
    { "macAcceptByPassUnknowDevice",    macAcceptByPassUnknowDevice,     wsbr_spinel_set_bool,                   SPINEL_PROP_WS_ACCEPT_BYPASS_UNKNOW_DEVICE,      },
    { "macEdfeForceStop",               macEdfeForceStop,                wsbr_spinel_set_bool,                   SPINEL_PROP_WS_EDFE_FORCE_STOP,                  },
    { "macAssociationPermit",           macAssociationPermit,            wsbr_spinel_set_bool,                   SPINEL_PROP_WS_ASSOCIATION_PERMIT,               },
    { "phyCurrentChannel",              phyCurrentChannel,               wsbr_spinel_set_u8,                     SPINEL_PROP_PHY_CHAN,                            },
    { "macAutoRequestKeyIdMode",        macAutoRequestKeyIdMode,         wsbr_spinel_set_u8,                     SPINEL_PROP_WS_AUTO_REQUEST_KEY_ID_MODE,         },
    { "macAutoRequestKeyIndex",         macAutoRequestKeyIndex,          wsbr_spinel_set_u8,                     SPINEL_PROP_WS_AUTO_REQUEST_KEY_INDEX,           },
    { "macAutoRequestSecurityLevel",    macAutoRequestSecurityLevel,     wsbr_spinel_set_u8,                     SPINEL_PROP_WS_AUTO_REQUEST_SECURITY_LEVEL,      },
    { "macBeaconPayloadLength",         macBeaconPayloadLength,          wsbr_spinel_set_u8,                     SPINEL_PROP_WS_BEACON_PAYLOAD_LENGTH,            },
    { "macMaxFrameRetries",             macMaxFrameRetries,              wsbr_spinel_set_u8,                     SPINEL_PROP_WS_MAX_FRAME_RETRIES,                },
    { "macTXPower",                     macTXPower,                      wsbr_spinel_set_u8,                     SPINEL_PROP_PHY_TX_POWER,                        },
    { "macCCAThreshold",                macCCAThreshold,                 wsbr_spinel_set_u8,                     SPINEL_PROP_PHY_CCA_THRESHOLD,                   },
    { "macPANId",                       macPANId,                        wsbr_spinel_set_u16,                    SPINEL_PROP_MAC_15_4_PANID,                      },
    { "macCoordShortAddress",           macCoordShortAddress,            wsbr_spinel_set_u16,                    SPINEL_PROP_WS_COORD_SHORT_ADDRESS,              },
    { "macShortAddress",                macShortAddress,                 wsbr_spinel_set_u16,                    SPINEL_PROP_MAC_15_4_SADDR,                      },
    { "macDeviceDescriptionPanIDUpdate",macDeviceDescriptionPanIDUpdate, wsbr_spinel_set_u16,                    SPINEL_PROP_WS_DEVICE_DESCRIPTION_PAN_ID_UPDATE, },
    { "macAckWaitDuration",             macAckWaitDuration,              wsbr_spinel_set_u16,                    SPINEL_PROP_WS_ACK_WAIT_DURATION,                },
    { "mac802_15_4Mode",                mac802_15_4Mode,                 wsbr_spinel_set_u32,                    SPINEL_PROP_WS_15_4_MODE,                        },
    { "macAutoRequestKeySource",        macAutoRequestKeySource,         wsbr_spinel_set_eui64,                  SPINEL_PROP_WS_AUTO_REQUEST_KEY_SOURCE,          },
    { "macCoordExtendedAddress",        macCoordExtendedAddress,         wsbr_spinel_set_eui64,                  SPINEL_PROP_WS_COORD_EXTENDED_ADDRESS,           },
    { "macDefaultKeySource",            macDefaultKeySource,             wsbr_spinel_set_eui64,                  SPINEL_PROP_WS_DEFAULT_KEY_SOURCE,               },
    { "macBeaconPayload",               macBeaconPayload,                wsbr_spinel_set_data,                   SPINEL_PROP_WS_BEACON_PAYLOAD,                   },
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
    } else {
        BUG("Unknown message");
    }
}

static void wsbr_mlme_get(const struct mac_api_s *api, const void *data)
{
    const mlme_get_t *req = data;
}

static void wsbr_mlme_scan(const struct mac_api_s *api, const void *data)
{
    WARN("not implemented");
}

static void wsbr_mlme_start(const struct mac_api_s *api, const void *data)
{
    const mlme_start_t *req = data;
}

static void wsbr_mlme_reset(const struct mac_api_s *api, const void *data)
{
    const mlme_reset_t *req = data;
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
    api->mlme_conf_cb(api, id, data);
}
void wsbr_mcps_req_ext(const struct mac_api_s *api,
                       const struct mcps_data_req_s *data,
                       const struct mcps_data_req_ie_list *ie_ext,
                       const struct channel_list_s *asynch_channel_list)
{
    // FIXME: use true symbol duration
    const unsigned int symbol_duration_us = 10;
    struct timespec ts;
    struct mcps_data_conf_s conf = {
        .msduHandle = data->msduHandle,
        .status = MLME_SUCCESS,
    };
    struct mcps_data_conf_payload_s data_conf = { };

    BUG_ON(!api);
    WARN("not implemented");
    clock_gettime(CLOCK_MONOTONIC, &ts);
    conf.timestamp = (ts.tv_sec * 1000000 + ts.tv_nsec / 1000) / symbol_duration_us;
    if (api->data_conf_ext_cb)
        api->data_conf_ext_cb(api, &conf, &data_conf);
    else
        api->data_conf_cb(api, &conf);
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
        // FIXME: replace with true MAC address from RCP ROM
        memcpy(mac64, "\x03\x14\x15\x92\x65\x35\x89\x79", 8);
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
