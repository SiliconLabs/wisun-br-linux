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
#include <stdint.h>
#include <sys/uio.h>

#include "stack/mac/fhss_ws_extension.h"
#include "stack/mac/platform/arm_hal_phy.h"

#define HIF_FHSS_TYPE_FFN_UC 0x00
#define HIF_FHSS_TYPE_FFN_BC 0x01
#define HIF_FHSS_TYPE_LFN_UC 0x02
#define HIF_FHSS_TYPE_LFN_BC 0x03
#define HIF_FHSS_TYPE_ASYNC  0x04
#define HIF_FHSS_TYPE_LFN_PA 0x06

struct ws_neighbor_class_entry;
struct fhss_ws_configuration;
struct phy_rf_channel_configuration;
struct mcps_data_req;
struct channel_list;
struct iobuf_write;
struct iobuf_read;
struct wsbr_ctxt;
struct os_ctxt;
struct net_if;
struct mcps_data_conf;
struct mcps_data_ind;
struct mcps_data_conf_payload;
struct mcps_data_ie_list;
typedef enum mlme_primitive mlme_primitive_e;

#define RCP_HAS_RESET          0x0001
#define RCP_HAS_HWADDR         0x0002
#define RCP_HAS_RF_CONFIG_LIST 0x0004
#define RCP_HAS_RF_CONFIG      0x0008

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
    void (*on_tx_cnf)(int8_t net_if_id, const struct mcps_data_conf *conf, const struct mcps_data_conf_payload *payload);
    void (*on_rx_ind)(int8_t net_if_id, const struct mcps_data_ind *conf, const struct mcps_data_ie_list *payload);
    void (*on_rx_err)(uint8_t src[8], uint8_t status);
    void (*on_crc_error)(struct os_ctxt *ctxt, uint16_t crc, uint32_t frame_len, uint8_t header, uint8_t irq_err_counter);

    uint32_t init_state;
    uint32_t version_api;
    uint32_t version_fw;
    const char *version_label;
    uint32_t neighbors_table_size;
    uint8_t lfn_limit;
    uint8_t  eui64[8];
    uint32_t frame_counter;
    struct rcp_rail_config *rail_config_list;
};

void rcp_noop(void);
void rcp_reset(void);
void rcp_reset_stack(void);
void rcp_start(uint16_t channel, uint16_t panid, bool coordinator);
void rcp_allocate_fhss(const struct fhss_ws_configuration *timing_info);
void rcp_register_fhss(void);
void rcp_unregister_fhss(void);
void rcp_release_fhss(void);
void rcp_get_hw_addr(void);
void rcp_get_rx_sensitivity(void);
void rcp_get_rf_config_list(void);
void rcp_set_rf_config_legacy(const struct phy_rf_channel_configuration *config);
void rcp_set_rf_config(const struct phy_rf_channel_configuration *config);
void rcp_set_regional_regulation(uint32_t val);
void rcp_set_rx_on_idle(bool enable);
void rcp_set_802154_mode(phy_802_15_4_mode_e val);
void rcp_set_ack_wait_duration(uint16_t val);
void rcp_set_cca_threshold(uint8_t number_of_channels, uint8_t default_dbm,
                           uint8_t high_limit, uint8_t low_limit);
void rcp_set_max_rf_retry(uint8_t max_cca_failure, uint8_t max_tx_failure,
                          uint16_t blacklist_min_ms, uint16_t blacklist_max_ms);
void rcp_set_max_mac_retry(uint8_t val);
void rcp_set_max_csma_backoffs(uint8_t val);
void rcp_set_min_be(uint8_t val);
void rcp_set_max_be(uint8_t val);
void rcp_set_max_async_duration(uint32_t val);
void rcp_set_tx_power(int8_t val);
void rcp_set_fhss_timings(const struct fhss_ws_configuration *timing_info);
void rcp_set_fhss_parent(const uint8_t parent[8],
                         const struct fhss_ws_neighbor_timing_info *timing_info,
                         bool force_synch);
void rcp_set_fhss_neighbor(const uint8_t neigh[8],
                           const struct fhss_ws_neighbor_timing_info *timing_info);
void rcp_drop_fhss_neighbor(const uint8_t eui64[8]);
void rcp_set_fhss_hop_count(int hop_count);
void rcp_set_coordinator_mac64(uint8_t val[8]);
void rcp_set_coordinator_mac16(uint16_t val);
void rcp_set_tx_allowance_level(fhss_ws_tx_allow_level_e normal,
                                fhss_ws_tx_allow_level_e expedited_forwarding);
void rcp_set_security(bool enable);
void rcp_set_accept_unknown_secured_frames(bool enable);
void rcp_set_frame_counter_per_key(bool enable);
void rcp_set_frame_counter(int slot, uint32_t val);
void rcp_get_frame_counter(int slot);
void rcp_set_key(uint8_t slot, const uint8_t *lookup_data, const uint8_t *key);
void rcp_set_default_key_source(const uint8_t lookup_data[8]);
void rcp_set_neighbor(uint8_t slot, uint16_t panid, uint16_t mac16,
                      uint8_t *mac64, uint32_t frame_counter);
void rcp_enable_mac_filter(bool forward_unknown);
void rcp_disable_mac_filter(void);
void rcp_add_mac_filter_entry(uint8_t mac64[8], bool forward);
void rcp_clear_mac_filters(void);

void rcp_abort_edfe(void);
void rcp_tx_req_legacy(const struct mcps_data_req *tx_req,
                       const struct iovec *header_ie,
                       const struct iovec *payload_ie,
                       const struct iovec *mpx_ie,
                       const struct channel_list *channel_list);
void rcp_tx_req(const uint8_t *frame, int frame_len,
                const struct ws_neighbor_class_entry *neighbor_ws,
                uint8_t handle, uint8_t fhss_type, bool is_edfe, uint8_t priority, uint8_t phy_id);
void rcp_tx_drop(uint8_t handle);

// Low-layer function to access the RCP
void rcp_rx(struct wsbr_ctxt *ctxt);
void rcp_tx(struct wsbr_ctxt *ctxt, struct iobuf_write *buf);

// Only used by the fuzzer
struct rcp_rx_cmds {
    uint32_t cmd;
    uint32_t prop;
    void (*fn)(struct wsbr_ctxt *ctxt, uint32_t prop, struct iobuf_read *buf);
};
extern struct rcp_rx_cmds rx_cmds[];
uint8_t rcp_get_spinel_hdr(void);

#endif
