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
#ifndef SL_WSRCP_MAC_H
#define SL_WSRCP_MAC_H
#include <stdint.h>
#include <stdbool.h>

#include "stack/mac/mac_api.h"

struct mcps_ack_data_payload;
struct wsmac_ctxt;

void wsmac_rx_host(struct wsmac_ctxt *ctxt);

void wsmac_reset_ind(struct wsmac_ctxt *ctxt, bool hw);

void wsmac_mcps_purge_confirm(const struct mac_api *mac_api,
                              struct mcps_purge_conf *data);
void wsmac_mlme_confirm(const struct mac_api *mac_api,
                        mlme_primitive_e id, const void *data);
void wsmac_mlme_indication(const struct mac_api *mac_api,
                           mlme_primitive_e id, const void *data);
void wsmac_mcps_data_confirm(const struct mac_api *mac_api,
                             const struct mcps_data_conf *data);
void wsmac_mcps_data_confirm_ext(const struct mac_api *mac_api,
                                 const struct mcps_data_conf *data,
                                 const struct mcps_data_conf_payload *conf_data);
void wsmac_mcps_data_indication(const struct mac_api *mac_api,
                                const struct mcps_data_ind *data);
void wsmac_mcps_data_indication_ext(const struct mac_api *mac_api,
                                    const struct mcps_data_ind *data,
                                    const struct mcps_data_ie_list *ie_ext);
void wsmac_mcps_ack_data_req_ext(const struct mac_api *mac_api,
                                 struct mcps_ack_data_payload *data,
                                 int8_t rssi, uint8_t lqi);
void wsmac_mcps_edfe_handler(const struct mac_api *mac_api,
                             struct mcps_edfe_response *response_message);

#endif
