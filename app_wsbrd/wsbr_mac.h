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
#ifndef WSBR_MAC_H
#define WSBR_MAC_H

#include "stack/mac/mac_api.h"

struct wsbr_ctxt;
struct iobuf_write;
struct iobuf_read;

#define RCP_HAS_RESET          0x0001
#define RCP_HAS_HWADDR         0x0002
#define RCP_HAS_RF_CONFIG_LIST 0x0004
#define RCP_HAS_RF_CONFIG      0x0008
#define RCP_INIT_DONE          0x0010

void wsbr_mac_store_rf_config_list(struct wsbr_ctxt *ctxt, struct iobuf_read *buf);
void wsbr_mac_print_rf_config_list(struct wsbr_ctxt *ctxt, struct iobuf_read *buf);
void wsbr_mac_handle_crc_error(struct wsbr_ctxt *ctxt, uint16_t crc, uint32_t frame_len,
                               uint8_t header, uint8_t irq_err_counter);
void wsbr_data_req_ext(const struct mac_api *api,
                       const struct mcps_data_req *data,
                       const struct mcps_data_req_ie_list *ie_ext);
uint8_t wsbr_mcps_purge(const struct mac_api *api, const mcps_purge_t *data);
int8_t wsbr_mac_addr_set(const struct mac_api *api, const uint8_t *mac64);
int8_t wsbr_mac_addr_get(const struct mac_api *api,
                     mac_extended_address_type_e type, uint8_t *mac64);
int8_t wsbr_mac_storage_sizes_get(const struct mac_api *api,
                                  struct mac_description_storage_size *buffer);
int8_t wsbr_mac_edfe_ext_init(struct mac_api *api,
                              mcps_edfe_handler *edfe_ind_cb);
int8_t wsbr_mac_init(struct mac_api *api,
                     mcps_data_confirm_ext *data_conf_cb,
                     mcps_data_indication_ext *data_ind_cb,
                     mcps_ack_data_req_ext *ack_data_req_cb,
                     mcps_purge_confirm *purge_conf_cb,
                     mlme_confirm *mlme_conf_cb,
                     mlme_indication *mlme_ind_cb,
                     int8_t parent_id);
#endif
