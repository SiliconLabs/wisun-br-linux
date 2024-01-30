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
#include "common/hif.h"

// TODO: drop legacy structures
struct fhss_ws_configuration;
struct mcps_data_cnf;
struct mcps_data_ind;
struct mcps_data_rx_ie_list;
struct os_ctxt;
struct phy_rf_channel_configuration;
struct wsbr_ctxt;
struct ws_neigh;

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
    void (*on_tx_cnf)(int8_t net_if_id, const struct mcps_data_cnf *conf, const struct mcps_data_rx_ie_list *payload);
    void (*on_rx_ind)(int8_t net_if_id, const struct mcps_data_ind *conf, const struct mcps_data_rx_ie_list *payload);
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

// Share rx buffer with legacy implementation to not allocate twice
extern uint8_t rcp_rx_buf[4096];

void rcp_rx(struct rcp *rcp);

void rcp_req_reset(struct rcp *rcp, bool bootload);
void rcp_set_host_api(struct rcp *rcp, uint32_t host_api_version);

void rcp_req_data_tx(struct rcp *rcp,
                     const uint8_t *frame, int frame_len,
                     uint8_t handle, uint8_t fhss_type,
                     const struct ws_neigh *neighbor_ws,
                     const struct hif_rate_info rate_list[4]);
void rcp_req_data_tx_abort(struct rcp *rcp, uint8_t handle);

// TODO: split into rcp_req_radio_enable() and rcp_set_filter_pan_id()
void rcp_req_radio_enable(struct rcp *rcp, uint16_t pan_id);
void rcp_req_radio_list(struct rcp *rcp);
void rcp_set_radio(struct rcp *rcp, const struct phy_rf_channel_configuration *rf_config);
void rcp_set_radio_regulation(struct rcp *rcp, enum hif_reg reg);
void rcp_set_radio_tx_power(struct rcp *rcp, int8_t power_dbm);

// TODO: split into rcp_set_fhss_{uc,ffn_bc,lfn_bc,async}()
void rcp_set_fhss(struct rcp *rcp, const struct fhss_ws_configuration *cfg);

void rcp_set_sec_key(struct rcp *rcp,
                     uint8_t key_index,
                     const uint8_t key[16],
                     uint32_t frame_counter);

void rcp_set_filter_src64(struct rcp *rcp,
                          const uint8_t eui64[][8],
                          uint8_t count,
                          bool allow);

#endif
