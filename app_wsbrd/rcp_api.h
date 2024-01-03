/*
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef RCP_API_H
#define RCP_API_H

#include <stdbool.h>
#include <stdint.h>

// TODO: drop legacy structures
struct mcps_data_cnf;
struct mcps_data_cnf_ie_list;
struct mcps_data_ind;
struct mcps_data_ind_ie_list;
struct os_ctxt;
struct wsbr_ctxt;

struct rcp_rail_config {
    int      index;
    uint32_t chan0_freq;
    uint32_t chan_spacing;
    uint16_t chan_count;
    uint8_t  rail_phy_mode_id;
    int      phy_mode_group;
};

struct rcp {
    int  (*device_tx)(struct os_ctxt *ctxt, const void *buf, unsigned int len);
    int  (*device_rx)(struct os_ctxt *ctxt, void *buf, unsigned int len);

    void (*on_reset)(struct wsbr_ctxt *ctxt);
    void (*on_tx_cnf)(int8_t net_if_id, const struct mcps_data_cnf *conf, const struct mcps_data_cnf_ie_list *payload);
    void (*on_rx_ind)(int8_t net_if_id, const struct mcps_data_ind *conf, const struct mcps_data_ind_ie_list *payload);
    void (*on_rx_err)(uint8_t src[8], uint8_t status);
    void (*on_crc_error)(struct os_ctxt *ctxt, uint16_t crc, uint32_t frame_len, uint8_t header, uint8_t irq_err_counter);
    void (*on_rx_frame_counter)(int8_t net_if_id, unsigned int gtk_index, uint32_t frame_counter);

    uint32_t init_state;
    uint32_t version_api;
    uint32_t version_fw;
    const char *version_label;
    uint32_t neighbors_table_size;
    uint8_t lfn_limit;
    uint8_t  eui64[8];
    struct rcp_rail_config *rail_config_list;
};

#endif
