/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include "nanostack/mlme.h"

#include "wsmac_mac.h"
#include "log.h"

void wsmac_mcps_data_confirm(const mac_api_t *mac_api, const mcps_data_conf_t *data)
{
    WARN("not implemented");
}

void wsmac_mcps_data_indication(const mac_api_t *mac_api, const mcps_data_ind_t *data)
{
    WARN("not implemented");
}

void wsmac_mcps_purge_confirm(const mac_api_t *mac_api, mcps_purge_conf_t *data)
{
    WARN("not implemented");
}

void wsmac_mlme_confirm(const mac_api_t *mac_api, mlme_primitive id, const void *data)
{
    WARN("not implemented");
}

void wsmac_mlme_indication(const mac_api_t *mac_api, mlme_primitive id, const void *data)
{
    WARN("not implemented");
}

void wsmac_mcps_data_confirm_ext(const mac_api_t *mac_api, const mcps_data_conf_t *data,
                                 const mcps_data_conf_payload_t *conf_data)
{
    WARN("not implemented");
}

void wsmac_mcps_data_indication_ext(const mac_api_t *mac_api, const mcps_data_ind_t *data,
                                    const mcps_data_ie_list_t *ie_ext)
{
    WARN("not implemented");
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
