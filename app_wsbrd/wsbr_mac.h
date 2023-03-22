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

void wsbr_mac_print_rf_config_list(struct wsbr_ctxt *ctxt, struct iobuf_read *buf);
void wsbr_mac_handle_crc_error(struct wsbr_ctxt *ctxt, uint16_t crc, uint32_t frame_len,
                               uint8_t header, uint8_t irq_err_counter);
void wsbr_data_req_ext(const struct mac_api *api,
                       const struct mcps_data_req *data,
                       const struct mcps_data_req_ie_list *ie_ext);
int8_t wsbr_mac_addr_set(const struct mac_api *api, const uint8_t *mac64);
int8_t wsbr_mac_addr_get(const struct mac_api *api,
                     mac_extended_address_type_e type, uint8_t *mac64);
#endif
