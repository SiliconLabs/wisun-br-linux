/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
/* MAC API imlementation */
#include <stdio.h>
#include <string.h>

#include "wsbr_mac.h"
#include "mac_api.h"
#include "log.h"

void wsbr_mlme(const struct mac_api_s *api, mlme_primitive id, const void *data)
{
    BUG_ON(!api);
}

void wsbr_mcps_req(const struct mac_api_s *api, const mcps_data_req_t *data)
{
    BUG_ON(!api);
}

uint8_t wsbr_mcps_purge(const struct mac_api_s *api, const mcps_purge_t *data)
{
    BUG_ON(!api);

    return 0;
}

int8_t wsbr_mac_addr_set(const struct mac_api_s *api, const uint8_t *mac64)
{
    BUG_ON(!api);
    BUG_ON(!mac64);

    return 0;
}

int8_t wsbr_mac_addr_get(const struct mac_api_s *api,
                     mac_extended_address_type type, uint8_t *mac64)
{
    BUG_ON(!api);
    BUG_ON(!mac64);

    memset(mac64, 0, 8);
    return 0;
}

int8_t wsbr_mac_storage_sizes_get(const struct mac_api_s *api,
                                  struct mac_description_storage_size_s *buffer)
{
    BUG_ON(!api);
    BUG_ON(!buffer);

    return 0;
}

int8_t wsbr_mac_mcps_ext_init(struct mac_api_s *api,
                              mcps_data_indication_ext *data_ind_cb,
                              mcps_data_confirm_ext *data_cnf_cb,
                              mcps_ack_data_req_ext *ack_data_req_cb)
{
    BUG_ON(!api);

    return -1;
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
