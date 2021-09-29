/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef WSBR_MAC_H
#define WSBR_MAC_H

#include "nanostack/mac_api.h"

struct wsbr_ctxt;
struct spinel_buffer;

uint8_t wsbr_get_spinel_hdr(struct wsbr_ctxt *ctxt);
void spinel_push_hdr_set_prop(struct wsbr_ctxt *ctxt, struct spinel_buffer *buf, unsigned int prop);
void spinel_push_hdr_get_prop(struct wsbr_ctxt *ctxt, struct spinel_buffer *buf, unsigned int prop);

void wsbr_rcp_get_hw_addr(struct wsbr_ctxt *ctxt);
void wsbr_rcp_reset(struct wsbr_ctxt *ctxt);

void wsbr_spinel_set_bool(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len);
void rcp_rx(struct wsbr_ctxt *ctxt);

void wsbr_mlme(const struct mac_api_s *api, mlme_primitive id, const void *data);
void wsbr_mcps_req(const struct mac_api_s *api, const mcps_data_req_t *data);
void wsbr_mcps_req_ext(const struct mac_api_s *api,
                       const struct mcps_data_req_s *data,
                       const struct mcps_data_req_ie_list *ie_ext,
                       const struct channel_list_s *asynch_channel_list,
                       mac_data_priority_t priority, uint8_t phy_id);
uint8_t wsbr_mcps_purge(const struct mac_api_s *api, const mcps_purge_t *data);
int8_t wsbr_mac_addr_set(const struct mac_api_s *api, const uint8_t *mac64);
int8_t wsbr_mac_addr_get(const struct mac_api_s *api,
                     mac_extended_address_type type, uint8_t *mac64);
int8_t wsbr_mac_storage_sizes_get(const struct mac_api_s *api,
                                  struct mac_description_storage_size_s *buffer);
int8_t wsbr_mac_mcps_ext_init(struct mac_api_s *api,
                              mcps_data_indication_ext *data_ind_cb,
                              mcps_data_confirm_ext *data_cnf_cb,
                              mcps_ack_data_req_ext *ack_data_req_cb);
int8_t wsbr_mac_edfe_ext_init(struct mac_api_s *api,
                              mcps_edfe_handler *edfe_ind_cb);
int8_t wsbr_mac_init(struct mac_api_s *api,
                     mcps_data_confirm *data_conf_cb,
                     mcps_data_indication *data_ind_cb,
                     mcps_purge_confirm *purge_conf_cb,
                     mlme_confirm *mlme_conf_cb,
                     mlme_indication *mlme_ind_cb,
                     int8_t parent_id);
int8_t wsbr_mac_mode_switch_resolver_set(mac_api_t *api,
                                         mode_switch_resolver *mode_resolver_cb,
                                         uint8_t base_phy_mode);
#endif
