/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
/* MAC API imlementation */
#include <time.h>
#include <stdio.h>
#include <string.h>

#include "wsbr_mac.h"
#include "mac_api.h"
#include "utils.h"
#include "log.h"

void wsbr_mlme(const struct mac_api_s *api, mlme_primitive id, const void *data)
{
    BUG_ON(!api);
}

void wsbr_mcps_req(const struct mac_api_s *api,
                   const struct mcps_data_req_s *data)
{
    // FIXME: use true symbol duration
    const unsigned int symbol_duration_us = 10;
    struct timespec ts;
    struct mcps_data_conf_s conf = {
        .msduHandle = data->msduHandle,
        .status = MLME_SUCCESS,
    };

    BUG_ON(!api);
    printf("%s:\n", __func__);
    pr_hex(data->msdu, data->msduLength);
    clock_gettime(CLOCK_MONOTONIC, &ts);
    conf.timestamp = (ts.tv_sec * 1000000 + ts.tv_nsec / 1000) / symbol_duration_us;
    api->data_conf_cb(api, &conf);
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
    printf("%s:\n", __func__);
    pr_hex(data->msdu, data->msduLength);
    clock_gettime(CLOCK_MONOTONIC, &ts);
    conf.timestamp = (ts.tv_sec * 1000000 + ts.tv_nsec / 1000) / symbol_duration_us;
    api->data_conf_ext_cb(api, &conf, &data_conf);
}

uint8_t wsbr_mcps_purge(const struct mac_api_s *api,
                        const struct mcps_purge_s *data)
{
    struct mcps_purge_conf_s conf = {
        .msduHandle = data->msduHandle,
    };

    BUG_ON(!api);
    api->purge_conf_cb(api, &conf);
    return 0;
}

int8_t wsbr_mac_addr_set(const struct mac_api_s *api, const uint8_t *mac64)
{
    struct wsbr_mac *ctxt = container_of(api, struct wsbr_mac, mac_api);

    BUG_ON(!api);
    BUG_ON(!mac64);

    memcpy(ctxt->dynamic_mac, mac64, 8);
    return 0;
}

int8_t wsbr_mac_addr_get(const struct mac_api_s *api,
                     mac_extended_address_type type, uint8_t *mac64)
{
    struct wsbr_mac *ctxt = container_of(api, struct wsbr_mac, mac_api);

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

    return -1;
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
