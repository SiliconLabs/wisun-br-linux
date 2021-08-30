/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef SL_WSRCP_MAC_H
#define SL_WSRCP_MAC_H

#include "nanostack/mac_api.h"

struct mcps_ack_data_payload;
struct wsmac_ctxt;

void wsmac_rx_host(struct wsmac_ctxt *ctxt);

void wsmac_reset_ind(struct wsmac_ctxt *ctxt, bool hw);

void wsmac_mcps_purge_confirm(const struct mac_api_s *mac_api,
                              struct mcps_purge_conf_s *data);
void wsmac_mlme_confirm(const struct mac_api_s *mac_api,
                        mlme_primitive id, const void *data);
void wsmac_mlme_indication(const struct mac_api_s *mac_api,
                           mlme_primitive id, const void *data);
void wsmac_mcps_data_confirm(const struct mac_api_s *mac_api,
                             const struct mcps_data_conf_s *data);
void wsmac_mcps_data_confirm_ext(const struct mac_api_s *mac_api,
                                 const struct mcps_data_conf_s *data,
                                 const struct mcps_data_conf_payload_s *conf_data);
void wsmac_mcps_data_indication(const struct mac_api_s *mac_api,
                                const struct mcps_data_ind_s *data);
void wsmac_mcps_data_indication_ext(const struct mac_api_s *mac_api,
                                    const struct mcps_data_ind_s *data,
                                    const struct mcps_data_ie_list *ie_ext);
void wsmac_mcps_ack_data_req_ext(const struct mac_api_s *mac_api,
                                 struct mcps_ack_data_payload *data,
                                 int8_t rssi, uint8_t lqi);
void wsmac_mcps_edfe_handler(const struct mac_api_s *mac_api,
                             struct mcps_edfe_response_s *response_message);

#endif
